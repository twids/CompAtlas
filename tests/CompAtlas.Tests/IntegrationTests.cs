using System.Net;
using System.Text;
using System.Text.Json;
using CompAtlas.Core;
using CompAtlas.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Xunit;

namespace CompAtlas.Tests;

public sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> handle) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.FromResult(handle(request));
    public static HttpResponseMessage Json(string value, HttpStatusCode status = HttpStatusCode.OK) => new(status) { Content = new StringContent(value, Encoding.UTF8, "application/json") };
}
public sealed class IntegrationTests
{
    [Fact]
    public async Task Analysis_waits_for_chain_completion_and_imports_deduplicated_findings()
    {
        await using var f = new Fixture(); await f.Seed();
        var dt = Guid.NewGuid(); var component = Guid.NewGuid(); f.Snapshot.DependencyTrackId = dt; await f.Db.SaveChangesAsync();
        var requests = new List<string>();
        using var client = new DependencyTrackClient(Options.Create(new AtlasOptions { DependencyTrackUrl = "https://dtrack.example.test/", DependencyTrackApiKey = "test-key" }), new HttpClient(new StubHandler(request =>
        {
            Assert.Equal("test-key", request.Headers.GetValues("X-Api-Key").Single()); requests.Add(request.Method + " " + request.RequestUri!.PathAndQuery);
            var path = request.RequestUri!.AbsolutePath;
            if (path.Contains("/component/project/", StringComparison.Ordinal)) return StubHandler.Json($"[{{\"uuid\":\"{component}\",\"name\":\"example\",\"version\":\"1.2.3\"}}]");
            if (path.EndsWith("/analyze", StringComparison.Ordinal)) return StubHandler.Json("{\"token\":\"analysis-token\"}");
            if (path.Contains("/bom/token/", StringComparison.Ordinal)) return StubHandler.Json("{\"processing\":false}");
            if (path.Contains("/finding/project/", StringComparison.Ordinal)) return StubHandler.Json($"[{{\"component\":{{\"uuid\":\"{component}\"}},\"vulnerability\":{{\"vulnId\":\"CVE-2026-1234\",\"source\":\"NVD\",\"severity\":\"HIGH\",\"aliases\":[{{\"cveId\":\"CVE-2026-1234\",\"ghsaId\":\"GHSA-test\"}}]}},\"analysis\":{{\"state\":\"NOT_SET\",\"isSuppressed\":false}}}}]");
            if (path.Contains("/violation/project/", StringComparison.Ordinal)) return StubHandler.Json("[]");
            throw new InvalidOperationException("Unexpected request: " + path);
        })));
        await new Analysis(f.Db, client, new AzureClient(Options.Create(new AtlasOptions())), f.Clock).Run(f.Snapshot.Id, default);
        Assert.Contains(requests, r => r.StartsWith("POST ", StringComparison.Ordinal) && r.EndsWith("/analyze", StringComparison.Ordinal));
        Assert.Contains(requests, r => r.Contains("bom/token/analysis-token", StringComparison.Ordinal));
        Assert.Equal("HIGH", (await f.Db.Findings.SingleAsync(x => x.SnapshotId == f.Snapshot.Id && x.Kind == FindingKind.Vulnerability)).Severity);
        Assert.Equal(f.Clock.Now, f.Snapshot.AnalyzedAt);
        Assert.Contains(await f.Db.Findings.Where(x => x.SnapshotId == f.Snapshot.Id).ToListAsync(), x => x.Identity == "gap:signature");
    }
    [Fact]
    public async Task External_review_edit_causes_conflict_without_overwrite()
    {
        await using var f = new Fixture(); await f.Seed();
        f.Snapshot.DependencyTrackId = Guid.NewGuid(); f.Finding.ExternalId = "CVE-2026-1234"; f.Finding.ExternalSource = "NVD";
        (await f.Db.Components.SingleAsync(c => c.SnapshotId == f.Snapshot.Id)).DependencyTrackId = Guid.NewGuid();
        var review = new Review { FindingId = f.Finding.Id, Assessment = Assessment.NotAffected, Reason = "Reviewed evidence", SyncState = SyncState.Pending, ExpectedExternalJson = Analysis.NormalizeAssessment(JsonDocument.Parse("{}").RootElement) };
        f.Db.Reviews.Add(review); await f.Db.SaveChangesAsync(); var writes = 0;
        using var client = new DependencyTrackClient(Options.Create(new AtlasOptions { DependencyTrackUrl = "https://dtrack.example.test/" }), new HttpClient(new StubHandler(request =>
        {
            if (request.Method == HttpMethod.Put) writes++;
            return request.RequestUri!.AbsolutePath.Contains("/vulnerability/", StringComparison.Ordinal) ? StubHandler.Json("{\"uuid\":\"" + Guid.NewGuid() + "\"}") : StubHandler.Json("{\"state\":\"EXPLOITABLE\",\"details\":\"External edit\"}");
        })));
        await new Analysis(f.Db, client, new AzureClient(Options.Create(new AtlasOptions())), f.Clock).SyncReview(review.Id, default);
        Assert.Equal(SyncState.Conflict, review.SyncState); Assert.Equal(0, writes);
    }
    [Fact]
    public async Task Upstream_error_does_not_mark_snapshot_successful()
    {
        await using var f = new Fixture(); await f.Seed(); f.Snapshot.State = SnapshotState.Pending; f.Snapshot.AnalyzedAt = null; await f.Db.SaveChangesAsync();
        using var client = new DependencyTrackClient(Options.Create(new AtlasOptions { DependencyTrackUrl = "https://dtrack.example.test/" }), new HttpClient(new StubHandler(_ => StubHandler.Json("{}", HttpStatusCode.ServiceUnavailable))));
        await Assert.ThrowsAsync<HttpRequestException>(() => new Analysis(f.Db, client, new AzureClient(Options.Create(new AtlasOptions())), f.Clock).Run(f.Snapshot.Id, default));
        Assert.Null(f.Snapshot.AnalyzedAt); Assert.True(f.Finding.Active);
    }
    [Fact]
    public async Task Known_malware_is_matched_by_ecosystem_name_and_exact_version()
    {
        await using var f = new Fixture(); await f.Seed();
        f.Db.MaliciousPackages.Add(new MaliciousPackage { AdvisoryId = "MAL-test", Ecosystem = "npm", Name = "example", VersionsJson = "[\"1.2.3\"]", Summary = "Known malicious package" }); await f.Db.SaveChangesAsync();
        await new Malware(f.Db, Options.Create(new AtlasOptions()), f.Clock).Match(f.Snapshot.Id, default);
        Assert.Single(await f.Db.Findings.Where(x => x.Kind == FindingKind.MaliciousPackage).ToListAsync());
        Assert.Equal(0, await f.Db.Findings.CountAsync(x => x.SnapshotId != f.Snapshot.Id && x.Kind == FindingKind.MaliciousPackage));
    }
}
