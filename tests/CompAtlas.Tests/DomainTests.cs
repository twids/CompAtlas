using System.Security.Claims;
using CompAtlas.Collector;
using CompAtlas.Core;
using CompAtlas.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace CompAtlas.Tests;

public sealed class DomainTests
{
    [Theory]
    [InlineData("S-1-5-21-100", 1)]
    [InlineData("S-1-5-21-200", 1)]
    [InlineData("S-1-5-21-300", 0)]
    [InlineData("S-1-5-21-400", 2)]
    [InlineData("S-1-5-21-123", 0)]
    public async Task Group_roles_do_not_grant_unrelated_access(string group, int expected)
    {
        await using var f = new Fixture(); await f.Seed();
        Assert.Equal(expected, (await f.Access.ReadableProjects(Fixture.User(group))).Length);
        Assert.False(await f.Access.CanReview(Fixture.User(group), f.Hidden.Id));
    }
    [Fact]
    public async Task Machine_claims_cannot_read_interactive_reports_even_with_groups()
    {
        await using var f = new Fixture(); await f.Seed();
        var user = Fixture.User("S-1-5-21-400"); ((ClaimsIdentity)user.Identity!).AddClaim(new Claim("atlas:machine", "true"));
        Assert.Empty(await f.Access.ReadableProjects(user));
    }
    [Fact]
    public async Task All_report_surfaces_filter_projects_including_explicit_snapshot_ids()
    {
        await using var f = new Fixture(); await f.Seed(); var user = Fixture.User("S-1-5-21-100");
        Assert.Single(await f.Reports.Findings(user)); Assert.Single(await f.Reports.Coverage(user));
        Assert.Single(await f.Reports.Packages(user, null, null, null));
        var secret = await f.Db.Snapshots.SingleAsync(s => s.Id != f.Snapshot.Id);
        Assert.Empty(await f.Reports.Findings(user, snapshot: secret.Id));
        Assert.Empty(await f.Reports.Packages(user, null, null, null, snapshot: secret.Id));
        Assert.DoesNotContain("Secret", Reports.Csv(await f.Reports.Findings(user)));
    }
    [Fact]
    public async Task Failed_new_snapshot_preserves_successful_report_but_coverage_shows_failure()
    {
        await using var f = new Fixture(); await f.Seed();
        f.Db.Snapshots.Add(new Snapshot
        {
            ApplicationId = f.Snapshot.ApplicationId,
            IsDefaultBranch = true,
            Commit = f.Repo.HeadCommit!,
            CreatedAt = f.Clock.Now.AddHours(1),
            State = SnapshotState.Failed,
            SubmissionKey = "failed"
        });
        await f.Db.SaveChangesAsync();
        Assert.Single(await f.Reports.Findings(Fixture.User("S-1-5-21-100")));
        Assert.Equal("Failed", (await f.Reports.Coverage(Fixture.User("S-1-5-21-100"))).Single().Status);
    }
    [Fact]
    public async Task Submission_is_idempotent_scoped_and_keeps_release_snapshots()
    {
        await using var f = new Fixture(); await f.Seed(); var service = new SubmissionService(f.Db, f.Queue, f.Clock);
        var input = new Submission(f.Repo.Id, "App", "app", new string('b', 40), "refs/heads/main", "42", null, Fixture.Bom(("lib", "1.0.0", "nuget")));
        var first = await service.Submit(input, f.Allowed.Id, default);
        var duplicate = await service.Submit(input, f.Allowed.Id, default);
        Assert.Equal(first.Id, duplicate.Id);
        var release = await service.Submit(input with { ReleaseId = "3" }, f.Allowed.Id, default);
        Assert.NotEqual(first.Id, release.Id);
        await Assert.ThrowsAsync<KeyNotFoundException>(() => service.Submit(input, f.Hidden.Id, default));
        Assert.Equal(2, await f.Db.Jobs.CountAsync(j => j.Kind == JobKind.Analyze));
    }
    [Fact]
    public async Task Reviews_are_scoped_concurrent_and_expire_without_suppression()
    {
        await using var f = new Fixture(); await f.Seed(); var reviews = new ReviewService(f.Db, f.Access, f.Queue, f.Clock);
        var request = new ReviewRequest(Assessment.InTriage, "Investigation pending", f.Clock.Now.AddDays(30), null);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => reviews.Record(Fixture.User("S-1-5-21-300"), f.Finding.Id, request, default));
        var review = await reviews.Record(Fixture.User("S-1-5-21-200"), f.Finding.Id, request, default);
        Assert.Single(await f.Reports.Findings(Fixture.User("S-1-5-21-100")), r => r.AcceptedUntil != null);
        await Assert.ThrowsAsync<InvalidOperationException>(() => reviews.Record(Fixture.User("S-1-5-21-200"), f.Finding.Id, request, default));
        f.Clock.Now = f.Clock.Now.AddDays(31); await reviews.Expire(default);
        Assert.NotNull(review.ExpiredAt);
        Assert.Null((await f.Reports.Findings(Fixture.User("S-1-5-21-100"))).Single().AcceptedUntil);
        Assert.Equal("{}", f.Finding.ExternalAssessmentJson);
        Assert.Equal(2, await f.Db.Audit.CountAsync());
    }
    [Fact]
    public async Task Queue_honors_project_scope_lease_and_retry_bound()
    {
        await using var f = new Fixture(); await f.Seed();
        var job = await f.Queue.Enqueue(JobKind.Collect, f.Repo.Id, "key", f.Allowed.Id);
        Assert.Equal(job.Id, (await f.Queue.Enqueue(JobKind.Collect, f.Repo.Id, "key", f.Allowed.Id)).Id);
        Assert.Null(await f.Queue.Claim(true, f.Hidden.Id, Guid.NewGuid(), default));
        var claimed = await f.Queue.Claim(true, f.Allowed.Id, Guid.NewGuid(), default);
        Assert.NotNull(claimed); Assert.Null(await f.Queue.Claim(true, f.Allowed.Id, Guid.NewGuid(), default));
        var original = claimed.LeaseOwner;
        f.Clock.Now = f.Clock.Now.AddHours(1);
        Assert.NotEqual(original, (await f.Queue.Claim(true, f.Allowed.Id, Guid.NewGuid(), default))!.LeaseOwner);
        f.Clock.Now = f.Clock.Now.AddHours(1); await f.Queue.Claim(true, f.Allowed.Id, Guid.NewGuid(), default);
        f.Clock.Now = f.Clock.Now.AddHours(1); Assert.Null(await f.Queue.Claim(true, f.Allowed.Id, Guid.NewGuid(), default));
        f.Db.ChangeTracker.Clear(); Assert.Equal(JobState.Failed, (await f.Db.Jobs.SingleAsync()).State);
    }
    [Theory]
    [InlineData("../app")]
    [InlineData("C:/app")]
    [InlineData("/app")]
    [InlineData("app//child")]
    public void Traversal_paths_are_rejected(string value) => Assert.Throws<ArgumentException>(() => SafeInput.RelativePath(value));
    [Theory]
    [InlineData("http://example.test")]
    [InlineData("https://user:secret@example.test")]
    [InlineData("file:///etc/passwd")]
    public void Insecure_or_credential_bearing_endpoints_are_rejected(string value) => Assert.Throws<ArgumentException>(() => SafeInput.HttpsEndpoint(value));
    [Theory]
    [InlineData("=WEBSERVICE(\"x\")")]
    [InlineData("  +SUM(1,2)")]
    [InlineData("@evil")]
    [InlineData("\tformula")]
    public void Csv_neutralizes_spreadsheet_formula_injection(string value) => Assert.StartsWith("\"'", SafeInput.Csv(value));
    [Fact]
    public void Bom_rejects_duplicates_and_limits_and_marks_missing_evidence()
    {
        var parsed = BomReader.Read(Fixture.Bom(("lib", "1.0.0", "nuget")), Guid.NewGuid());
        Assert.Contains(parsed.Gaps, g => g.Contains("License")); Assert.Contains(parsed.Gaps, g => g.Contains("origin"));
        Assert.Throws<ArgumentException>(() => BomReader.Read("{\"bomFormat\":\"SPDX\"}", Guid.NewGuid()));
        Assert.Throws<ArgumentException>(() => BomReader.Read(new string('x', SafeInput.MaxBomBytes + 1), Guid.NewGuid()));
        var json = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"components\":[{\"name\":\"a\",\"bom-ref\":\"same\"},{\"name\":\"b\",\"bom-ref\":\"same\"}]}";
        Assert.Throws<ArgumentException>(() => BomReader.Read(json, Guid.NewGuid()));
    }
    [Theory]
    [InlineData("nuget", "[1.0.0,2.0.0)", "1.9.0", true)]
    [InlineData("npm", "[1.0.0,2.0.0)", "2.0.0", false)]
    [InlineData("pypi", "[1.0,2.0)", "1.2.post1", true)]
    [InlineData("pypi", "[1.0,2.0)", "1.0rc1", false)]
    [InlineData("pypi", "[1.0,2.0)", "1.0.dev1", false)]
    [InlineData("pypi", "=1.0+local", "1.0+local", true)]
    public void Version_ranges_use_ecosystem_ordering(string ecosystem, string range, string version, bool expected) =>
        Assert.Equal(expected, VersionFilter.Parse(ecosystem, range)(version));
    [Fact]
    public async Task Unknown_licenses_and_same_package_names_remain_separate()
    {
        await using var f = new Fixture(); await f.Seed();
        f.Db.Components.Add(new Component { SnapshotId = f.Snapshot.Id, Name = "example", Version = "1.2.3", Ecosystem = "nuget", BomRef = "nuget" });
        await f.Db.SaveChangesAsync();
        var result = await f.Reports.Packages(Fixture.User("S-1-5-21-100"), "nuget", "example", "=1.2.3");
        Assert.Equal("nuget", Assert.Single(result).Ecosystem); Assert.Null(result[0].License);
    }
    [Fact]
    public async Task Audit_events_cannot_be_edited()
    {
        await using var f = new Fixture(); f.Db.Audit.Add(new AuditEvent { Action = "Original" }); await f.Db.SaveChangesAsync();
        (await f.Db.Audit.SingleAsync()).Action = "Modified";
        await Assert.ThrowsAsync<InvalidOperationException>(() => f.Db.SaveChangesAsync());
    }
    [Fact]
    public void Legacy_xml_cannot_resolve_external_entities()
    {
        var dir = Path.Combine(Path.GetTempPath(), "compatlas-test-" + Guid.NewGuid()); Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "packages.config"), "<!DOCTYPE packages [<!ENTITY xxe SYSTEM 'file:///C:/Windows/win.ini'>]><packages>&xxe;</packages>");
            Assert.Throws<System.Xml.XmlException>(() => Inventory.Create(dir));
        }
        finally { Directory.Delete(dir, true); }
    }
    [Fact]
    public void Conservative_collector_preserves_unknown_versions_and_file_hashes()
    {
        var dir = Path.Combine(Path.GetTempPath(), "compatlas-test-" + Guid.NewGuid()); Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "package.json"), "{\"dependencies\":{\"old-angular\":\"^1.0.0\"}}"); File.WriteAllText(Path.Combine(dir, "angular.min.js"), "/* unknown */");
            var parsed = BomReader.Read(Inventory.Create(dir), Guid.NewGuid());
            Assert.All(parsed.Components, c => Assert.Null(c.Version)); Assert.Contains(parsed.Components, c => c.Hash != null);
            Assert.Contains(parsed.Gaps, g => g.Contains("partial coverage"));
        }
        finally { Directory.Delete(dir, true); }
    }
}
