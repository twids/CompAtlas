using System.Diagnostics;
using CompAtlas.Core;
using CompAtlas.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace CompAtlas.Tests;

public sealed class ScaleAndEvidenceTests
{
    [Fact]
    public void Nested_components_are_searchable_and_disconnected_nodes_are_not_mislabeled_transitive()
    {
        var json="""
            {"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"bom-ref":"root"}},
            "components":[{"name":"direct","bom-ref":"a","components":[{"name":"child","bom-ref":"b"}]},{"name":"unconnected","bom-ref":"c"}],
            "dependencies":[{"ref":"root","dependsOn":["a"]},{"ref":"a","dependsOn":["b"]}]}
            """;
        var parsed=BomReader.Read(json,Guid.NewGuid()); Assert.Equal(3,parsed.Components.Count);
        Assert.True(parsed.Components.Single(c=>c.BomRef=="a").Direct); Assert.False(parsed.Components.Single(c=>c.BomRef=="b").Direct);
        Assert.Null(parsed.Components.Single(c=>c.BomRef=="c").Direct);
    }
    [Fact]
    public async Task Reporting_handles_one_hundred_repositories_without_cross_project_leakage()
    {
        await using var f = new Fixture(); await f.Seed();
        for (var i = 0; i < 98; i++)
        {
            var repo = new Repository { ProjectId = f.Allowed.Id, ExternalId = Guid.NewGuid(), Name = "Repo-" + i };
            var app = new Application { RepositoryId = repo.Id, RelativePath = ".", Name = "App" };
            var snapshot = new Snapshot { ApplicationId = app.Id, IsDefaultBranch = true, SubmissionKey = "scale-" + i, CreatedAt = f.Clock.Now, AnalyzedAt = f.Clock.Now, State = SnapshotState.Complete };
            f.Db.AddRange(repo, app, snapshot);
            for (var j = 0; j < 100; j++) f.Db.Components.Add(new Component { SnapshotId = snapshot.Id, BomRef = "lib-" + j, Name = "lib-" + j, Version = "1.0.0", Ecosystem = "nuget" });
        }
        await f.Db.SaveChangesAsync(); f.Db.ChangeTracker.Clear();
        var timer = Stopwatch.StartNew(); var user = Fixture.User("S-1-5-21-100");
        Assert.Equal(99, (await f.Reports.Coverage(user)).Count);
        Assert.Equal(9801, (await f.Reports.Packages(user, null, null, null)).Count);
        Assert.Single(await f.Reports.Findings(user));
        Assert.True(timer.Elapsed < TimeSpan.FromSeconds(30), "Synthetic reporting exceeded 30 seconds; real nightly collection must still be measured independently.");
    }
    [Fact]
    public async Task Manual_file_identification_creates_new_evidence_and_requires_reviewer()
    {
        await using var f = new Fixture(); await f.Seed();
        var service = new SubmissionService(f.Db, f.Queue, f.Clock);
        var json = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"components\":[{\"name\":\"vendor.js\",\"bom-ref\":\"file\",\"hashes\":[{\"alg\":\"SHA-256\",\"content\":\"" + new string('a', 64) + "\"}]}]}";
        var original = await service.Submit(new Submission(f.Repo.Id, "Legacy", "legacy", new string('a', 40), "refs/heads/main", null, null, json), f.Allowed.Id, default);
        var declarations = new ManualDeclarations(f.Db, f.Access, service);
        var request = new ManualDeclarationRequest(original.Id, "file", "angular", "1.2.3", "npm", "MIT", "Verified against approved package hash.");
        await Assert.ThrowsAsync<KeyNotFoundException>(() => declarations.Record(Fixture.User("S-1-5-21-100"), request, default));
        var derived = await declarations.Record(Fixture.User("S-1-5-21-200"), request, default);
        Assert.NotEqual(original.Id, derived.Id); Assert.Equal(json, original.BomJson);
        var component = await f.Db.Components.SingleAsync(c => c.SnapshotId == derived.Id);
        Assert.Equal("1.2.3", component.Version); Assert.StartsWith("Manually reviewed in CompAtlas", component.Confidence);
        Assert.Equal(new string('a', 64), component.Hash);
    }
    [Theory]
    [InlineData("1.1.0", true)]
    [InlineData("2.0.0", false)]
    public void Malicious_advisory_ranges_respect_exclusive_fixed_boundary(string version, bool expected)
    {
        Assert.Equal(expected, Malware.AffectedByRange("npm", version, "[{\"type\":\"SEMVER\",\"events\":[{\"introduced\":\"0\"},{\"fixed\":\"2.0.0\"}]}]"));
    }
    [Fact]
    public void Untrusted_sbom_cannot_claim_authenticated_manual_review()
    {
        var json = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"components\":[{\"name\":\"test\",\"properties\":[{\"name\":\"compatlas:evidence\",\"value\":\"Manually reviewed by administrator\"}]}]}";
        Assert.StartsWith("Declared evidence:", BomReader.Read(json, Guid.NewGuid()).Components.Single().Confidence);
    }
    [Fact]
    public void Credential_bearing_urls_in_inventory_are_rejected()
    {
        var json = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"components\":[{\"name\":\"test\",\"externalReferences\":[{\"type\":\"distribution\",\"url\":\"https://user:secret@feed.test/pkg\"}]}]}";
        Assert.Throws<ArgumentException>(() => BomReader.Read(json, Guid.NewGuid()));
    }
}
