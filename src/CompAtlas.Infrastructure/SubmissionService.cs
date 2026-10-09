using System.Text.Json;
using CompAtlas.Core;
using Microsoft.EntityFrameworkCore;

namespace CompAtlas.Infrastructure;

public sealed class SubmissionService(AtlasDb db, JobQueue queue, TimeProvider clock)
{
    public async Task<Snapshot> Submit(Submission input, Guid projectId, CancellationToken ct)
    {
        var repo = await db.Repositories.SingleOrDefaultAsync(r => r.Id == input.RepositoryId && r.ProjectId == projectId && r.Enabled, ct)
            ?? throw new KeyNotFoundException();
        SafeInput.Text(input.Application, 200, "application name");
        var path = SafeInput.RelativePath(input.RelativePath);
        if (!System.Text.RegularExpressions.Regex.IsMatch(input.Commit, "^[a-fA-F0-9]{40}$", System.Text.RegularExpressions.RegexOptions.CultureInvariant))
            throw new ArgumentException("A full 40-character Git commit is required.");
        SafeInput.Text(input.Branch, 400, "branch");
        if (input.BuildId != null) SafeInput.Text(input.BuildId, 100, "build ID");
        if (input.ReleaseId != null) SafeInput.Text(input.ReleaseId, 100, "release ID");
        var bomHash = Secrets.Hash(input.BomJson);
        var key = Secrets.Hash(JsonSerializer.Serialize(new { input.RepositoryId, path, input.Commit, input.Branch, input.BuildId, input.ReleaseId, bomHash }));
        var existing = await db.Snapshots.SingleOrDefaultAsync(s => s.SubmissionKey == key, ct);
        if (existing != null) return existing;
        var snapshot = new Snapshot
        {
            Commit = input.Commit.ToLowerInvariant(),
            Branch = input.Branch,
            BuildId = input.BuildId,
            ReleaseId = input.ReleaseId,
            IsDefaultBranch = input.Branch == repo.DefaultBranch,
            BomJson = input.BomJson,
            BomHash = bomHash,
            SubmissionKey = key,
            CreatedAt = clock.GetUtcNow(),
            State = SnapshotState.Pending
        };
        var parsed = BomReader.Read(input.BomJson, snapshot.Id);
        snapshot.Coverage = parsed.Gaps.Count > 0 ? "Partial — see evidence gaps" : "Declared inventory; completeness not independently verified";
        await using var tx = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, ct);
        var app = await db.Applications.SingleOrDefaultAsync(a => a.RepositoryId == repo.Id && a.RelativePath == path, ct);
        if (app == null) { app = new Application { RepositoryId = repo.Id, RelativePath = path, Name = input.Application }; db.Applications.Add(app); }
        snapshot.ApplicationId = app.Id;
        db.Snapshots.Add(snapshot);
        db.Components.AddRange(parsed.Components);
        foreach (var gap in parsed.Gaps.Distinct())
            db.Findings.Add(new Finding
            {
                SnapshotId = snapshot.Id,
                Kind = FindingKind.EvidenceGap,
                Identity = "gap:" + Secrets.Hash(gap),
                Title = gap,
                Severity = "Information"
            });
        if (input.BuildId == null) db.Findings.Add(new Finding
        {
            SnapshotId = snapshot.Id,
            Kind = FindingKind.EvidenceGap,
            Identity = "gap:build",
            Title = "Build-to-commit linkage is not available.",
            Severity = "Information"
        });
        db.Audit.Add(new AuditEvent { ActorSid = "machine", Action = "SnapshotSubmitted", ProjectId = projectId, Target = snapshot.Id.ToString() });
        await db.SaveChangesAsync(ct);
        await queue.Enqueue(JobKind.Analyze, snapshot.Id, "analyze:" + snapshot.Id, projectId, ct: ct);
        await tx.CommitAsync(ct);
        return snapshot;
    }
}
