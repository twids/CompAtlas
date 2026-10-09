using System.Security.Claims;
using System.Text.Json;
using CompAtlas.Core;
using CompAtlas.Infrastructure;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace CompAtlas.Tests;

public sealed class FixedClock : TimeProvider
{
    public DateTimeOffset Now { get; set; } = new(2026, 10, 9, 12, 0, 0, TimeSpan.Zero);
    public override DateTimeOffset GetUtcNow() => Now;
}
public sealed class Fixture : IAsyncDisposable
{
    public SqliteConnection Connection { get; } = new("Data Source=:memory:");
    public AtlasDb Db { get; }
    public FixedClock Clock { get; } = new();
    public SourceProject Allowed { get; } = new() { Name = "Allowed", ExternalId = Guid.NewGuid() };
    public SourceProject Hidden { get; } = new() { Name = "Confidential", ExternalId = Guid.NewGuid() };
    public Repository Repo { get; private set; } = null!;
    public Repository HiddenRepo { get; private set; } = null!;
    public Snapshot Snapshot { get; private set; } = null!;
    public Finding Finding { get; private set; } = null!;
    public ProjectAccess Access => new(Db);
    public JobQueue Queue => new(Db, Clock);
    public Reports Reports => new(Db, Access, Clock);
    public Fixture()
    {
        Connection.Open();
        Db = new AtlasDb(new DbContextOptionsBuilder<AtlasDb>().UseSqlite(Connection).Options);
        Db.Database.EnsureCreated();
    }
    public async Task Seed()
    {
        var connection = new SourceConnection { Name = "Test collection", BaseUrl = "https://devops.example.test/collection/" };
        Allowed.ConnectionId = Hidden.ConnectionId = connection.Id;
        Db.Add(connection); Db.AddRange(Allowed, Hidden);
        Repo = new Repository { ProjectId = Allowed.Id, ExternalId = Guid.NewGuid(), Name = "VisibleRepo", HeadCommit = new string('a', 40) };
        HiddenRepo = new Repository { ProjectId = Hidden.Id, ExternalId = Guid.NewGuid(), Name = "SecretRepo" };
        Db.AddRange(Repo, HiddenRepo);
        Db.RoleBindings.AddRange(new RoleBinding { GroupSid = "S-1-5-21-100", ProjectId = Allowed.Id, Role = AccessRole.ProjectReader },
            new RoleBinding { GroupSid = "S-1-5-21-200", ProjectId = Allowed.Id, Role = AccessRole.ProjectReviewer },
            new RoleBinding { GroupSid = "S-1-5-21-300", Role = AccessRole.Administrator },
            new RoleBinding { GroupSid = "S-1-5-21-400", Role = AccessRole.SecurityReader });
        foreach (var repo in new[] { Repo, HiddenRepo })
        {
            var app = new Application { RepositoryId = repo.Id, Name = "Web", RelativePath = "." };
            var snapshot = new Snapshot
            {
                ApplicationId = app.Id,
                Commit = new string('a', 40),
                Branch = "refs/heads/main",
                IsDefaultBranch = true,
                SubmissionKey = Secrets.Hash(repo.Id.ToString()),
                State = SnapshotState.Complete,
                CreatedAt = Clock.Now,
                AnalyzedAt = Clock.Now,
                Coverage = "Declared inventory"
            };
            var component = new Component { SnapshotId = snapshot.Id, Name = repo == Repo ? "example" : "secret-package", Version = "1.2.3", Ecosystem = "npm", BomRef = "pkg" };
            var finding = new Finding { SnapshotId = snapshot.Id, ComponentId = component.Id, Identity = "vuln:" + component.Id + ":CVE-2026-1234", Kind = FindingKind.Vulnerability, Title = repo == Repo ? "Visible finding" : "Secret vulnerability" };
            Db.AddRange(app, snapshot, component, finding);
            if (repo == Repo) { Snapshot = snapshot; Finding = finding; }
        }
        await Db.SaveChangesAsync();
    }
    public static ClaimsPrincipal User(params string[] groups) => new(new ClaimsIdentity(new[] {
        new Claim(ClaimTypes.PrimarySid, "S-1-5-21-999"), new Claim(ClaimTypes.Name, "DOMAIN\\reviewer")
    }.Concat(groups.Select(g => new Claim(ClaimTypes.GroupSid, g))), "Test"));
    public static string Bom(params (string Name, string Version, string Ecosystem)[] packages) => JsonSerializer.Serialize(new
    {
        bomFormat = "CycloneDX",
        specVersion = "1.6",
        components = packages.Select((p, i) => new Dictionary<string, object>
        {
            ["bom-ref"] = "pkg-" + i,
            ["name"] = p.Name,
            ["version"] = p.Version,
            ["purl"] = "pkg:" + p.Ecosystem + "/" + p.Name + "@" + p.Version
        }).ToArray()
    });
    public async ValueTask DisposeAsync() { await Db.DisposeAsync(); await Connection.DisposeAsync(); }
}
