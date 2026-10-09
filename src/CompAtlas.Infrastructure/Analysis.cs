using System.Text.Json;
using CompAtlas.Core;
using Microsoft.EntityFrameworkCore;

namespace CompAtlas.Infrastructure;

public sealed class Analysis(AtlasDb db, DependencyTrackClient client, AzureClient azure, TimeProvider clock)
{
    public async Task Run(Guid snapshotId, CancellationToken ct)
    {
        var snapshot = await db.Snapshots.SingleAsync(s => s.Id == snapshotId, ct);
        var app = await db.Applications.SingleAsync(a => a.Id == snapshot.ApplicationId, ct);
        var repo = await db.Repositories.SingleAsync(r => r.Id == app.RepositoryId, ct);
        var project = await db.Projects.SingleAsync(p => p.Id == repo.ProjectId, ct);
        var connection = await db.Connections.SingleAsync(c => c.Id == project.ConnectionId, ct);
        var initial = snapshot.AnalyzedAt == null;
        if (snapshot.ProcessingToken == null && snapshot.DependencyTrackId == null)
        {
            var upload = await client.Upload(snapshot, app, ct);
            snapshot.ProcessingToken = upload.Str("token") ?? throw new InvalidOperationException("Missing BOM processing token.");
            snapshot.State = SnapshotState.Processing;
            await db.SaveChangesAsync(ct);
        }
        if (snapshot.ProcessingToken != null)
        {
            var done = false;
            for (var i = 0; i < 300; i++)
            {
                var token = await client.Get("bom/token/" + Uri.EscapeDataString(snapshot.ProcessingToken), ct);
                if (token.Obj("processing").ValueKind == JsonValueKind.False) { done = true; break; }
                await Task.Delay(TimeSpan.FromSeconds(2), clock, ct);
            }
            if (!done) throw new TimeoutException("Dependency-Track BOM processing did not complete within ten minutes.");
        }
        if (snapshot.DependencyTrackId == null)
        {
            var result = await client.Get("project/lookup?name=" + Uri.EscapeDataString("CompAtlas:" + app.Id) + "&version=" + snapshot.Id, ct);
            snapshot.DependencyTrackId = Guid.Parse(result.Str("uuid")!);
            snapshot.ProcessingToken = null;
        }
        var dtId = snapshot.DependencyTrackId.Value;
        var components = await db.Components.Where(c => c.SnapshotId == snapshot.Id).ToListAsync(ct);
        foreach (var external in await client.Pages("component/project/" + dtId, ct))
        {
            var matching = components.FirstOrDefault(c => external.Str("purl") != null ? c.Purl == external.Str("purl") : c.Name == external.Str("name") && c.Version == external.Str("version"));
            if (matching != null) matching.DependencyTrackId = Guid.Parse(external.Str("uuid")!);
        }
        // Explicitly request analysis and wait for its chain token, not merely BOM ingestion.
        var analysis = await client.Post("finding/project/" + dtId + "/analyze", ct);
        var analysisToken = analysis.Str("token") ?? throw new InvalidOperationException("Missing vulnerability analysis token.");
        snapshot.ProcessingToken = analysisToken;
        await db.SaveChangesAsync(ct);
        var analysisComplete = false;
        for (var attempt = 0; attempt < 300; attempt++)
        {
            var token = await client.Get("bom/token/" + Uri.EscapeDataString(analysisToken), ct);
            if (token.Obj("processing").ValueKind == JsonValueKind.False) { analysisComplete = true; break; }
            await Task.Delay(TimeSpan.FromSeconds(2), clock, ct);
        }
        if (!analysisComplete) throw new TimeoutException("Vulnerability analysis did not complete within ten minutes.");
        snapshot.ProcessingToken = null;
        // This endpoint returns all findings and does not implement pagination.
        var findingResponse = await client.Get("finding/project/" + dtId + "?suppressed=true", ct);
        if (findingResponse.ValueKind != JsonValueKind.Array) throw new InvalidOperationException("Unexpected findings response.");
        var externalFindings = findingResponse.EnumerateArray().Select(x => x.Clone()).ToList();
        var violations = await client.Pages("violation/project/" + dtId, ct);
        await using var resultTransaction = await db.Database.BeginTransactionAsync(ct);
        var previous = await db.Findings.Where(f => f.SnapshotId == snapshotId && (f.Kind == FindingKind.Vulnerability || f.Kind == FindingKind.License)).ToListAsync(ct);
        foreach (var old in previous) old.Active = false;
        foreach (var external in externalFindings)
        {
            var vulnerability = external.Obj("vulnerability");
            var component = components.FirstOrDefault(c => c.DependencyTrackId?.ToString() == external.Obj("component").Str("uuid"));
            var source = vulnerability.Str("source") ?? "Unknown";
            var id = vulnerability.Str("vulnId") ?? throw new InvalidOperationException("Finding lacks vulnerability identity.");
            var aliases = vulnerability.Items("aliases").SelectMany(a => new[] { a.Str("cveId"), a.Str("ghsaId"), a.Str("osvId"), a.Str("vulnId") }).OfType<string>().Append(id).Distinct().Order().ToArray();
            var canonical = aliases.FirstOrDefault(a => a.StartsWith("CVE-", StringComparison.Ordinal)) ?? aliases.First();
            var occurrenceId = component?.Id.ToString() ?? external.Obj("component").Str("uuid") ?? Secrets.Hash(external.Obj("component").GetRawText());
            var identity = "vuln:" + occurrenceId + ":" + canonical;
            if (component == null) AddGap(snapshot, "unmapped-component-" + occurrenceId, "A vulnerability's upstream component could not be mapped to inventory; affected-package evidence requires review.");
            var finding = previous.FirstOrDefault(f => f.Identity == identity) ?? db.Findings.Local.FirstOrDefault(f => f.SnapshotId == snapshotId && f.Identity == identity);
            if (finding == null) { finding = new Finding { SnapshotId = snapshotId, ComponentId = component?.Id, Kind = FindingKind.Vulnerability, Identity = identity }; db.Findings.Add(finding); }
            finding.Active = true;
            finding.Title = vulnerability.Str("title") ?? id;
            finding.Severity = vulnerability.Str("severity") ?? "Unknown";
            finding.Detail = vulnerability.Str("description");
            finding.Recommendation = vulnerability.Str("recommendation");
            finding.AliasesJson = JsonSerializer.Serialize(aliases);
            finding.ExternalId = id;
            finding.ExternalSource = source;
            finding.ExternalAssessmentJson = NormalizeAssessment(external.Obj("analysis"));
            finding.ObservedAt = clock.GetUtcNow();
        }
        foreach (var external in violations)
        {
            if (external.Str("type") != "LICENSE") continue;
            var component = components.FirstOrDefault(c => c.DependencyTrackId?.ToString() == external.Obj("component").Str("uuid"));
            var identity = "license:" + (external.Str("uuid") ?? Secrets.Hash(external.GetRawText()));
            var finding = previous.FirstOrDefault(f => f.Identity == identity);
            if (finding == null) { finding = new Finding { SnapshotId = snapshotId, ComponentId = component?.Id, Kind = FindingKind.License, Identity = identity }; db.Findings.Add(finding); }
            finding.Active = true;
            finding.Title = external.Obj("policyCondition").Obj("policy").Str("name") ?? "License policy violation";
            finding.Severity = "Review";
            finding.Detail = "Dependency-Track license-policy result. Organizational policy must be configured before interpreting compliance.";
            finding.ObservedAt = clock.GetUtcNow();
        }
        snapshot.Traceability = "Not assessed";
        if (snapshot.BuildId != null && long.TryParse(snapshot.BuildId, out _))
        {
            try
            {
                var build = await azure.Get(connection, project.ExternalId + "/_apis/build/builds/" + snapshot.BuildId, false, ct);
                if (build.Str("sourceVersion") == snapshot.Commit && build.Obj("repository").Str("id") == repo.ExternalId.ToString())
                {
                    snapshot.Traceability = "Azure DevOps-reported build-to-commit linkage";
                    try
                    {
                        var timeline = await azure.Get(connection, project.ExternalId + "/_apis/build/builds/" + snapshot.BuildId + "/timeline", false, ct);
                        var stages = timeline.Items("records").Where(r => r.Str("type") == "Stage").ToArray();
                        if (stages.Length > 0) snapshot.Traceability += "; pipeline stages: " + string.Join(", ", stages.Select(s => s.Str("name") + " (" + s.Str("state") + "/" + s.Str("result") + ")"));
                        else AddGap(snapshot, "yaml-stage-evidence", "No YAML deployment stage evidence was returned; build linkage alone does not establish deployment.");
                    }
                    catch (HttpRequestException) { AddGap(snapshot, "yaml-stage-unavailable", "YAML pipeline stage evidence is unavailable."); }
                }
                else AddGap(snapshot, "traceability-mismatch", "Submitted commit/repository does not match the Azure DevOps build.");
                if (snapshot.ReleaseId != null && long.TryParse(snapshot.ReleaseId, out _))
                {
                    var release = await azure.Get(connection, project.ExternalId + "/_apis/release/releases/" + snapshot.ReleaseId, true, ct);
                    var linked = release.Items("artifacts").Any(a => a.Str("type") == "Build" && a.Obj("definitionReference").Obj("version").Str("id") == snapshot.BuildId &&
                        a.Obj("definitionReference").Obj("project").Str("id") == project.ExternalId.ToString());
                    if (linked) snapshot.Traceability += "; Classic Release-to-build linkage; environments: " + string.Join(", ", release.Items("environments").Select(e => e.Str("name") + " (" + e.Str("status") + ")"));
                    else AddGap(snapshot, "release-mismatch", "Release-to-build linkage could not be established.");
                }
            }
            catch (HttpRequestException) { AddGap(snapshot, "traceability-unavailable", "Azure DevOps build/release evidence is unavailable."); }
        }
        AddGap(snapshot, "signature", "Artifact signature verification has not been assessed.");
        AddGap(snapshot, "intelligence-coverage", "Dependency-Track advisory-source freshness and reachability analysis are not independently verified by CompAtlas.");
        snapshot.AnalyzedAt = clock.GetUtcNow();
        snapshot.LastError = null;
        snapshot.State = snapshot.Coverage.StartsWith("Partial", StringComparison.Ordinal) ? SnapshotState.Partial : SnapshotState.Complete;
        var intelligence = await db.IntelligenceSources.FindAsync(["Dependency-Track findings retrieval"], ct);
        if (intelligence == null) { intelligence = new IntelligenceSource { Name = "Dependency-Track findings retrieval" }; db.IntelligenceSources.Add(intelligence); }
        intelligence.LastSuccess = clock.GetUtcNow(); intelligence.LastError = null;
        intelligence.RecordCount = externalFindings.Count;
        await db.SaveChangesAsync(ct);
        await resultTransaction.CommitAsync(ct);
        _ = initial;
    }
    private void AddGap(Snapshot s, string identity, string title)
    {
        if (!db.Findings.Local.Any(f => f.SnapshotId == s.Id && f.Identity == "gap:" + identity) && !db.Findings.Any(f => f.SnapshotId == s.Id && f.Identity == "gap:" + identity))
            db.Findings.Add(new Finding { SnapshotId = s.Id, Identity = "gap:" + identity, Kind = FindingKind.EvidenceGap, Title = title, Severity = "Information" });
    }
    public static string NormalizeAssessment(JsonElement external) => JsonSerializer.Serialize(new
    {
        state = external.Str("state") ?? "NOT_SET",
        justification = external.Str("justification"),
        response = external.Str("response"),
        details = external.Str("details"),
        suppressed = external.Obj("isSuppressed").ValueKind == JsonValueKind.True
    });

    public async Task SyncReview(Guid id, CancellationToken ct)
    {
        var review = await db.Reviews.SingleAsync(r => r.Id == id, ct);
        var finding = await db.Findings.SingleAsync(f => f.Id == review.FindingId, ct);
        var snapshot = await db.Snapshots.SingleAsync(s => s.Id == finding.SnapshotId, ct);
        var component = await db.Components.SingleAsync(c => c.Id == finding.ComponentId, ct);
        if (review.SyncState != SyncState.Pending) return;
        var latest = await db.Reviews.Where(r => r.FindingId == finding.Id).OrderByDescending(r => r.CreatedAt).ThenByDescending(r => r.Id).Select(r => r.Id).FirstAsync(ct);
        if (latest != id) { review.SyncState = SyncState.Conflict; await db.SaveChangesAsync(ct); return; }
        var vulnerability = await client.Get("vulnerability/source/" + Uri.EscapeDataString(finding.ExternalSource!) + "/vuln/" + Uri.EscapeDataString(finding.ExternalId!), ct);
        var vulnerabilityUuid = vulnerability.Str("uuid") ?? throw new InvalidOperationException("Upstream vulnerability identity is unavailable.");
        var external = await client.Get("analysis?project=" + snapshot.DependencyTrackId + "&component=" + component.DependencyTrackId +
            "&vulnerability=" + vulnerabilityUuid, ct);
        var current = NormalizeAssessment(external);
        var state = review.Assessment switch
        {
            Assessment.FalsePositive => "FALSE_POSITIVE",
            Assessment.NotAffected => "NOT_AFFECTED",
            Assessment.Exploitable => "EXPLOITABLE",
            Assessment.InTriage => "IN_TRIAGE",
            Assessment.Resolved => "RESOLVED",
            _ => "NOT_SET"
        };
        if (current != review.ExpectedExternalJson)
        {
            // Allow replay after a successful upstream write whose local acknowledgement was interrupted.
            if (external.Str("state") == state && external.Str("details") == "CompAtlas review " + review.Id + ": " + review.Reason)
            { review.SyncState = SyncState.Synchronized; finding.ExternalAssessmentJson = current; }
            else review.SyncState = SyncState.Conflict;
            await db.SaveChangesAsync(ct); return;
        }
        // Dependency-Track has no compare-and-swap API. Restrict external write access operationally.
        await client.Put("analysis", new
        {
            project = snapshot.DependencyTrackId,
            component = component.DependencyTrackId,
            vulnerability = vulnerability.Str("uuid"),
            analysisState = state,
            analysisDetails = "CompAtlas review " + review.Id + ": " + review.Reason,
            isSuppressed = false
        }, ct);
        review.SyncState = SyncState.Synchronized;
        finding.ExternalAssessmentJson = NormalizeAssessment(await client.Get("analysis?project=" + snapshot.DependencyTrackId + "&component=" + component.DependencyTrackId +
            "&vulnerability=" + vulnerability.Str("uuid"), ct));
        await db.SaveChangesAsync(ct);
    }
}
