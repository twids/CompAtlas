using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using CompAtlas.Core;
using CompAtlas.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace CompAtlas.Tests;

public sealed class TestAuthentication(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("X-Test-Group", out var group)) return Task.FromResult(AuthenticateResult.NoResult());
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(Fixture.User(group.ToString()), Scheme.Name)));
    }
}
public sealed class TestSchemeProvider(IOptions<AuthenticationOptions> options) : AuthenticationSchemeProvider(options)
{
    // TestServer has no connection-level Negotiate protocol feature. Keep machine auth real; replace Windows negotiation only in tests.
    public override Task<IEnumerable<AuthenticationScheme>> GetRequestHandlerSchemesAsync() => Task.FromResult(Enumerable.Empty<AuthenticationScheme>());
}
public sealed class AtlasFactory : WebApplicationFactory<Program>
{
    public Fixture Data { get; } = new();
    public string Token { get; } = Secrets.Create();
    public AtlasFactory()
    {
        Data.Seed().GetAwaiter().GetResult();
        Data.Db.MachineCredentials.Add(new MachineCredential
        {
            ProjectId = Data.Allowed.Id,
            Name = "Test",
            SecretHash = Secrets.Hash(Token),
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(10),
            CanCollect = true
        });
        Data.Db.SaveChangesAsync().GetAwaiter().GetResult();
    }
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.ConfigureServices(services =>
        {
            services.Configure<Microsoft.AspNetCore.Http.ProblemDetailsOptions>(o => o.CustomizeProblemDetails = context =>
                context.ProblemDetails.Detail = context.HttpContext.Features.Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerFeature>()?.Error.ToString());
            services.RemoveAll<DbContextOptions<AtlasDb>>();
            services.RemoveAll<IDbContextOptionsConfiguration<AtlasDb>>();
            services.AddDbContext<AtlasDb>(o => o.UseSqlite(Data.Connection));
            services.AddAuthentication(o => { o.DefaultAuthenticateScheme = "Test"; o.DefaultChallengeScheme = "Test"; o.DefaultForbidScheme = "Test"; })
                .AddScheme<AuthenticationSchemeOptions, TestAuthentication>("Test", _ => { });
            services.AddSingleton<IAuthenticationSchemeProvider, TestSchemeProvider>();
        });
    }
    public HttpClient Client(string? group = null, string? token = null)
    {
        var client = CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        if (group != null) client.DefaultRequestHeaders.Add("X-Test-Group", group);
        if (token != null) client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }
}
public sealed class WebTests(AtlasFactory factory) : IClassFixture<AtlasFactory>
{
    [Theory]
    [InlineData("/")]
    [InlineData("/Packages")]
    [InlineData("/Operations")]
    [InlineData("/Administration")]
    [InlineData("/api/v1/findings")]
    public async Task Unauthenticated_requests_are_rejected(string path)
    { using var client = factory.Client(); Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync(path)).StatusCode); }
    [Theory]
    [InlineData("/")]
    [InlineData("/Packages")]
    [InlineData("/Operations")]
    [InlineData("/api/v1/findings")]
    [InlineData("/api/v1/reports/findings.csv")]
    public async Task Report_pages_and_exports_never_contain_hidden_project_data(string path)
    {
        using var client = factory.Client("S-1-5-21-100"); var response = await client.GetAsync(path);
        Assert.True(response.StatusCode == HttpStatusCode.OK, await response.Content.ReadAsStringAsync());
        var body = await response.Content.ReadAsStringAsync(); Assert.DoesNotContain("SecretRepo", body); Assert.DoesNotContain("secret-package", body);
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Contains("no-store", response.Headers.CacheControl!.ToString());
    }
    [Fact]
    public async Task Administrator_is_not_implicitly_a_reader_or_reviewer()
    {
        using var client = factory.Client("S-1-5-21-300");
        Assert.Equal("[]", await client.GetStringAsync("/api/v1/findings"));
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/Administration")).StatusCode);
    }
    [Fact]
    public async Task Reader_cannot_open_administration_or_hidden_finding()
    {
        using var client = factory.Client("S-1-5-21-100");
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/Administration")).StatusCode);
        var hidden = await factory.Data.Db.Findings.SingleAsync(f => f.Title == "Secret vulnerability");
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/Finding/" + hidden.Id)).StatusCode);
    }
    [Fact]
    public async Task Unsafe_interactive_requests_require_antiforgery_token()
    {
        using var client = factory.Client("S-1-5-21-200");
        var response = await client.PostAsync("/Finding/" + factory.Data.Finding.Id, new FormUrlEncodedContent(new Dictionary<string, string> { { "Reason", "forged" }, { "Assessment", "FalsePositive" } }));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
    [Fact]
    public async Task Interactive_api_rejects_forged_requests()
    {
        using var client = factory.Client("S-1-5-21-200");
        var response = await client.PostAsJsonAsync("/api/v1/findings/" + factory.Data.Finding.Id + "/reviews",
            new ReviewRequest(Assessment.FalsePositive, "forged", null, null));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        response = await client.PostAsync("/api/v1/collections?repository=" + factory.Data.Repo.Id, null);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Revoked_or_expired_machine_credentials_are_rejected(bool revoked)
    {
        var secret = Secrets.Create();
        factory.Data.Db.MachineCredentials.Add(new MachineCredential
        {
            ProjectId = factory.Data.Allowed.Id, Name = "Invalidated", SecretHash = Secrets.Hash(secret),
            Revoked = revoked, ExpiresAt = revoked ? DateTimeOffset.UtcNow.AddDays(1) : DateTimeOffset.UtcNow.AddDays(-1), CanCollect = true
        });
        await factory.Data.Db.SaveChangesAsync();
        using var client = factory.Client(token: secret);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsync("/api/v1/collection/claim", null)).StatusCode);
    }
    [Fact]
    public async Task Machine_upload_is_project_scoped_and_invalid_bearer_is_rejected()
    {
        var input = new Submission(factory.Data.HiddenRepo.Id, "App", ".", new string('a', 40), "refs/heads/main", null, null, Fixture.Bom(("test", "1.0.0", "npm")));
        using var valid = factory.Client(token: factory.Token);
        Assert.Equal(HttpStatusCode.NotFound, (await valid.PostAsJsonAsync("/api/v1/sboms", input)).StatusCode);
        var accepted = await valid.PostAsJsonAsync("/api/v1/sboms", input with { RepositoryId = factory.Data.Repo.Id, RelativePath = "machine" });
        Assert.Equal(HttpStatusCode.Accepted, accepted.StatusCode);
        using var invalid = factory.Client(token: new string('0', 64));
        Assert.Equal(HttpStatusCode.Unauthorized, (await invalid.PostAsJsonAsync("/api/v1/sboms", input)).StatusCode);
    }
    [Fact]
    public async Task Forged_completion_cannot_finish_another_collectors_job()
    {
        using var client = factory.Client(token: factory.Token);
        var response = await client.PostAsJsonAsync("/api/v1/collection/" + Guid.NewGuid() + "/complete", new Completion(Guid.NewGuid(), true));
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
    [Fact]
    public async Task Accessible_markup_has_language_skip_link_captions_and_no_inline_script()
    {
        using var client = factory.Client("S-1-5-21-100"); var response = await client.GetAsync("/"); var html = await response.Content.ReadAsStringAsync();
        Assert.Contains("lang=\"en\"", html); Assert.Contains("Skip to main content", html); Assert.Contains("<caption>", html);
        Assert.Contains("scope=\"col\"", html); Assert.DoesNotContain("<script", html);
        Assert.Contains("script-src 'none'", response.Headers.GetValues("Content-Security-Policy").Single());
    }
}
