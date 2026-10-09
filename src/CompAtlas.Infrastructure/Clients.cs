using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using CompAtlas.Core;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace CompAtlas.Infrastructure;

public static class SecureHttp
{
    public static HttpClient Create(string? proxy, bool defaultCredentials = false)
    {
        var handler = new HttpClientHandler { AllowAutoRedirect = false, UseDefaultCredentials = defaultCredentials };
        if (!string.IsNullOrWhiteSpace(proxy))
        {
            if (!Uri.TryCreate(proxy, UriKind.Absolute, out var proxyUri) || proxyUri.Scheme is not ("http" or "https") || proxyUri.UserInfo.Length > 0)
                throw new ArgumentException("Proxy must be an operator-configured HTTP/HTTPS URL without embedded credentials.");
            handler.Proxy = new WebProxy(proxyUri) { Credentials = CredentialCache.DefaultNetworkCredentials };
            handler.UseProxy = true;
        }
        return new HttpClient(handler) { Timeout = TimeSpan.FromMinutes(2), MaxResponseContentBufferSize = 32 * 1024 * 1024 };
    }
    public static Uri Endpoint(string baseUrl, string relative) => new(SafeInput.HttpsEndpoint(baseUrl.TrimEnd('/') + "/"), relative);
    public static async Task<JsonElement> Json(HttpResponseMessage response, CancellationToken ct)
    {
        using (response)
        {
            if (!response.IsSuccessStatusCode) throw new HttpRequestException($"Upstream returned HTTP {(int)response.StatusCode}.");
            if (response.StatusCode == HttpStatusCode.NoContent || response.Content.Headers.ContentLength == 0)
                return JsonDocument.Parse("{}").RootElement.Clone();
            var bytes = await response.Content.ReadAsByteArrayAsync(ct);
            if (bytes.Length > 32 * 1024 * 1024) throw new InvalidOperationException("Upstream response exceeds limit.");
            using var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 64 });
            return doc.RootElement.Clone();
        }
    }
}

public sealed class AzureClient(IOptions<AtlasOptions> options)
{
    public async Task<JsonElement> Get(SourceConnection connection, string route, bool release, CancellationToken ct)
    {
        // The on-premises release API uses the configured collection host, never a client-supplied host.
        _ = release;
        using var client = SecureHttp.Create(options.Value.ProxyUrl, options.Value.AzureUseDefaultCredentials);
        if (options.Value.AzureTokens.TryGetValue(connection.Id.ToString(), out var token))
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(":" + token)));
        var separator = route.Contains('?') ? "&" : "?";
        return await SecureHttp.Json(await client.GetAsync(SecureHttp.Endpoint(connection.BaseUrl,
            route + separator + "api-version=" + Uri.EscapeDataString(connection.ApiVersion)), ct), ct);
    }
    public async Task<List<JsonElement>> List(SourceConnection connection, string route, bool release, CancellationToken ct)
    {
        var all = new List<JsonElement>();
        using var client = SecureHttp.Create(options.Value.ProxyUrl, options.Value.AzureUseDefaultCredentials);
        if (options.Value.AzureTokens.TryGetValue(connection.Id.ToString(), out var token))
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(":" + token)));
        string? continuation = null;
        for (var page = 0; page < 1000; page++)
        {
            var separator = route.Contains('?') ? "&" : "?";
            var url = route + separator + "api-version=" + Uri.EscapeDataString(connection.ApiVersion) + "&$top=100" +
                (continuation == null ? "" : "&continuationToken=" + Uri.EscapeDataString(continuation));
            var response = await client.GetAsync(SecureHttp.Endpoint(connection.BaseUrl, url), ct);
            continuation = response.Headers.TryGetValues("x-ms-continuationtoken", out var values) ? values.FirstOrDefault() : null;
            var json = await SecureHttp.Json(response, ct);
            all.AddRange(json.Items("value"));
            if (continuation == null) return all;
        }
        throw new InvalidOperationException("Azure DevOps pagination limit reached.");
    }
    public async Task Probe(SourceConnection connection, CancellationToken ct)
    {
        foreach (var version in new[] { "7.1", "7.0", "6.0" })
        {
            connection.ApiVersion = version;
            try { await Get(connection, "_apis/projects?$top=1", false, ct); return; }
            catch (HttpRequestException) when (version != "6.0") { }
        }
    }
}

public sealed class DependencyTrackClient(IOptions<AtlasOptions> options, HttpClient? overrideClient = null) : IDisposable
{
    private readonly HttpClient client = overrideClient ?? SecureHttp.Create(options.Value.ProxyUrl);
    public void Dispose() => client.Dispose();
    private async Task<JsonElement> Send(HttpMethod method, string path, object? body, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, SecureHttp.Endpoint(options.Value.DependencyTrackUrl, "api/v1/" + path));
        request.Headers.Add("X-Api-Key", options.Value.DependencyTrackApiKey);
        if (body != null) request.Content = JsonContent.Create(body);
        return await SecureHttp.Json(await client.SendAsync(request, ct), ct);
    }
    public Task<JsonElement> Get(string path, CancellationToken ct) => Send(HttpMethod.Get, path, null, ct);
    public Task<JsonElement> Put(string path, object body, CancellationToken ct) => Send(HttpMethod.Put, path, body, ct);
    public Task<JsonElement> Post(string path, CancellationToken ct) => Send(HttpMethod.Post, path, null, ct);
    public Task<JsonElement> Upload(Snapshot snapshot, Application application, CancellationToken ct) => Put("bom", new
    {
        projectName = "CompAtlas:" + application.Id,
        projectVersion = snapshot.Id.ToString(),
        autoCreate = true,
        bom = Convert.ToBase64String(Encoding.UTF8.GetBytes(snapshot.BomJson))
    }, ct);
    public async Task<List<JsonElement>> Pages(string path, CancellationToken ct)
    {
        var result = new List<JsonElement>();
        for (var page = 1; page <= 1000; page++)
        {
            var json = await Get(path + (path.Contains('?') ? "&" : "?") + "pageNumber=" + page + "&pageSize=100", ct);
            if (json.ValueKind != JsonValueKind.Array) throw new InvalidOperationException("Unexpected Dependency-Track response.");
            var items = json.EnumerateArray().Select(x => x.Clone()).ToArray();
            result.AddRange(items);
            if (items.Length < 100) return result;
        }
        throw new InvalidOperationException("Dependency-Track pagination limit reached.");
    }
}

public sealed class Discovery(AtlasDb db, AzureClient client, JobQueue queue, TimeProvider clock)
{
    public async Task Run(Guid connectionId, CancellationToken ct)
    {
        var connection = await db.Connections.SingleAsync(c => c.Id == connectionId && c.Enabled, ct);
        await client.Probe(connection, ct);
        var seen = new HashSet<Guid>();
        foreach (var p in await client.List(connection, "_apis/projects", false, ct))
        {
            var externalId = Guid.Parse(p.Str("id")!);
            var project = await db.Projects.SingleOrDefaultAsync(x => x.ConnectionId == connectionId && x.ExternalId == externalId, ct);
            if (project == null) { project = new SourceProject { ConnectionId = connectionId, ExternalId = externalId }; db.Projects.Add(project); }
            project.Name = p.Str("name") ?? externalId.ToString();
            await db.SaveChangesAsync(ct);
            foreach (var r in await client.List(connection, externalId + "/_apis/git/repositories", false, ct))
            {
                var repoId = Guid.Parse(r.Str("id")!);
                var repo = await db.Repositories.SingleOrDefaultAsync(x => x.ProjectId == project.Id && x.ExternalId == repoId, ct);
                if (repo == null) { repo = new Repository { ProjectId = project.Id, ExternalId = repoId }; db.Repositories.Add(repo); }
                repo.Name = r.Str("name") ?? repoId.ToString();
                repo.DefaultBranch = r.Str("defaultBranch") ?? "refs/heads/main";
                var cloneUrl = SafeInput.HttpsEndpoint(r.Str("remoteUrl") ?? "");
                if (cloneUrl.Authority != SafeInput.HttpsEndpoint(connection.BaseUrl).Authority) throw new InvalidOperationException("Repository clone host differs from configured collection host.");
                repo.CloneUrl = cloneUrl.AbsoluteUri;
                var refs = await client.List(connection, externalId + "/_apis/git/repositories/" + repoId + "/refs?filter=" + Uri.EscapeDataString(repo.DefaultBranch[5..]), false, ct);
                repo.HeadCommit = refs.FirstOrDefault(x => x.Str("name") == repo.DefaultBranch).Str("objectId");
                repo.LastSeen = clock.GetUtcNow();
                seen.Add(repo.Id);
                await db.SaveChangesAsync(ct);
                if (repo.Enabled && repo.HeadCommit != null)
                {
                    var appIds = await db.Applications.Where(a => a.RepositoryId == repo.Id).Select(a => a.Id).ToArrayAsync(ct);
                    var already = await db.Snapshots.AnyAsync(s => appIds.Contains(s.ApplicationId) && s.Commit == repo.HeadCommit && s.IsDefaultBranch &&
                        (s.State == SnapshotState.Complete || s.State == SnapshotState.Partial), ct);
                    if (!already) await queue.Enqueue(JobKind.Collect, repo.Id, "collect:" + repo.Id + ":" + repo.HeadCommit + ":" + clock.GetUtcNow().ToString("yyyyMMdd"),
                        project.Id, JsonSerializer.Serialize(new { Commit = repo.HeadCommit, Branch = repo.DefaultBranch }), ct);
                }
            }
        }
        connection.LastDiscovery = clock.GetUtcNow();
        connection.LastError = null;
        await db.SaveChangesAsync(ct);
        // Do not delete repositories when access disappears: preserve history and mark freshness through LastSeen.
    }
}
