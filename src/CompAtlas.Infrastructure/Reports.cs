using System.Security.Claims;
using System.Text;
using CompAtlas.Core;
using Microsoft.EntityFrameworkCore;
using NuGet.Versioning;

namespace CompAtlas.Infrastructure;

public sealed class Reports(AtlasDb db, ProjectAccess access, TimeProvider clock)
{
    private async Task<Guid[]> SelectedSnapshots(Guid[] projects, Guid? repo, Guid? snapshot, CancellationToken ct)
    {
        var applications = await (from a in db.Applications
                                  join r in db.Repositories on a.RepositoryId equals r.Id
                                  where projects.Contains(r.ProjectId) && (repo == null || r.Id == repo)
                                  select a.Id).ToArrayAsync(ct);
        var candidates = db.Snapshots.Where(s => applications.Contains(s.ApplicationId));
        if (snapshot != null) return await candidates.Where(s => s.Id == snapshot).Select(s => s.Id).ToArrayAsync(ct);
        var rows = await (from s in candidates
                          join a in db.Applications on s.ApplicationId equals a.Id
                          join r in db.Repositories on a.RepositoryId equals r.Id
                          where s.IsDefaultBranch && (s.State == SnapshotState.Complete || s.State == SnapshotState.Partial)
                          select new { s.Id, s.ApplicationId, s.CreatedAt, s.Commit, r.HeadCommit }).ToArrayAsync(ct);
        return rows.GroupBy(s => s.ApplicationId).Select(g => g.OrderByDescending(s => s.HeadCommit != null && s.Commit == s.HeadCommit).ThenByDescending(s => s.CreatedAt).First().Id).ToArray();
    }
    public async Task<List<FindingRow>> Findings(ClaimsPrincipal user, Guid? project = null, Guid? repo = null, Guid? snapshot = null, CancellationToken ct = default)
    {
        var projects = await access.ReadableProjects(user, ct);
        if (project != null) projects = projects.Where(p => p == project).ToArray();
        var selected = await SelectedSnapshots(projects, repo, snapshot, ct);
        var rows = await (from f in db.Findings.AsNoTracking()
                          join s in db.Snapshots on f.SnapshotId equals s.Id
                          join a in db.Applications on s.ApplicationId equals a.Id
                          join r in db.Repositories on a.RepositoryId equals r.Id
                          join p in db.Projects on r.ProjectId equals p.Id
                          join c in db.Components on f.ComponentId equals c.Id into cs
                          from c in cs.DefaultIfEmpty()
                          where projects.Contains(p.Id) && selected.Contains(s.Id) && f.Active
                          select new { F = f, S = s, A = a, R = r, P = p, C = c }).ToListAsync(ct);
        var ids = rows.Select(x => x.F.Id).ToArray();
        var reviews = (await db.Reviews.AsNoTracking().Where(x => ids.Contains(x.FindingId)).ToListAsync(ct))
            .GroupBy(x => x.FindingId).ToDictionary(g => g.Key, g => g.OrderByDescending(x => x.CreatedAt).ThenByDescending(x => x.Id).First());
        return rows.Select(x =>
        {
            var review = reviews.GetValueOrDefault(x.F.Id); return new FindingRow(x.F.Id, x.P.Id, x.P.Name,
            x.R.Id, x.R.Name, x.A.Name, x.S.Id, x.S.Commit, x.S.BuildId, x.S.ReleaseId, x.C?.Name ?? "", x.C?.Ecosystem ?? "",
            x.C?.Version, x.F.Kind, x.F.Identity, x.F.Severity, x.F.Title, x.F.Detail, review?.Assessment ?? Assessment.Unreviewed,
            review?.AcceptedUntil > clock.GetUtcNow() && review.ExpiredAt == null ? review.AcceptedUntil : null,
            x.S.CreatedAt, x.S.AnalyzedAt, x.S.Coverage, review?.SyncState.ToString() ?? "Not reviewed", x.C?.License);
        }).ToList();
    }
    public async Task<List<PackageRow>> Packages(ClaimsPrincipal user, string? ecosystem, string? name, string? range, Guid? repo = null, Guid? snapshot = null, CancellationToken ct = default)
    {
        if (ecosystem != null) SafeInput.Text(ecosystem, 32, "ecosystem");
        if (name != null) SafeInput.Text(name, 400, "package search");
        if (range != null) SafeInput.Text(range, 128, "version filter");
        if (range != null && string.IsNullOrWhiteSpace(ecosystem)) throw new ArgumentException("Select an ecosystem before filtering versions.");
        var projects = await access.ReadableProjects(user, ct);
        var selected = await SelectedSnapshots(projects, repo, snapshot, ct);
        var rows = await (from c in db.Components.AsNoTracking()
                          join s in db.Snapshots on c.SnapshotId equals s.Id
                          join a in db.Applications on s.ApplicationId equals a.Id
                          join r in db.Repositories on a.RepositoryId equals r.Id
                          join p in db.Projects on r.ProjectId equals p.Id
                          where projects.Contains(p.Id) && selected.Contains(s.Id) && (ecosystem == null || c.Ecosystem == ecosystem)
                              && (name == null || c.Name.Contains(name))
                          select new PackageRow(p.Id, p.Name, r.Id, r.Name, a.Name, s.Id, c.Ecosystem, c.Name, c.Version, c.License,
                              c.Direct, c.Confidence, c.Origin, s.CreatedAt, s.Coverage)).ToListAsync(ct);
        if (range == null) return rows;
        // Explicit portable syntax avoids pretending NuGet ranges are Python PEP 440 or npm expressions.
        var matches = VersionFilter.Parse(ecosystem!, range);
        return rows.Where(x => matches(x.Version)).ToList();
    }
    public async Task<List<CoverageRow>> Coverage(ClaimsPrincipal user, CancellationToken ct = default)
    {
        var projects = await access.ReadableProjects(user, ct);
        var repos = await (from r in db.Repositories
                           join p in db.Projects on r.ProjectId equals p.Id
                           where projects.Contains(p.Id)
                           select new { R = r, P = p }).ToListAsync(ct);
        var repoIds = repos.Select(x => x.R.Id).ToArray();
        var apps = await db.Applications.Where(a => repoIds.Contains(a.RepositoryId)).ToListAsync(ct);
        var appIds = apps.Select(a => a.Id).ToArray();
        var snapshots = await db.Snapshots.Where(s => appIds.Contains(s.ApplicationId) && s.IsDefaultBranch).ToListAsync(ct);
        return repos.Select(x =>
        {
            var ids = apps.Where(a => a.RepositoryId == x.R.Id).Select(a => a.Id).ToHashSet();
            var latestByApp = snapshots.Where(s => ids.Contains(s.ApplicationId)).GroupBy(s => s.ApplicationId)
                .Select(g => g.OrderByDescending(s => x.R.HeadCommit != null && s.Commit == x.R.HeadCommit).ThenByDescending(s => s.CreatedAt).First()).ToArray();
            var latest = latestByApp.OrderByDescending(s => s.CreatedAt).FirstOrDefault();
            var status = latest == null ? "Not collected" : latestByApp.Any(s => s.State == SnapshotState.Failed) ? "Failed" :
                latestByApp.Any(s => s.State is SnapshotState.Pending or SnapshotState.Processing) ? "Pending" :
                latestByApp.Any(s => x.R.HeadCommit != null && s.Commit != x.R.HeadCommit) ? "Source changed — awaiting collection" :
                x.R.LastSeen != null && x.R.LastSeen < clock.GetUtcNow().AddHours(-36) ? "Discovery stale" :
                latestByApp.Any(s => s.AnalyzedAt == null || s.AnalyzedAt < clock.GetUtcNow().AddHours(-36)) ? "Stale" :
                latestByApp.Any(s => s.State == SnapshotState.Partial) ? "Partial" : "Analyzed";
            return new CoverageRow(x.P.Id, x.P.Name, x.R.Id, x.R.Name, latest?.Id, latest?.CreatedAt, latest?.AnalyzedAt,
                status, latest?.Coverage ?? "Unknown", latest?.Traceability ?? "Not assessed", latest?.SignatureEvidence ?? "Not assessed");
        }).ToList();
    }
    public static string Csv(IEnumerable<FindingRow> rows)
    {
        var text = new StringBuilder("Project,Repository,Application,Package,Ecosystem,Version,Kind,Identity,Severity,Title,Assessment,AcceptedUntil,CollectedAt,AnalyzedAt,Coverage,SyncStatus\r\n");
        foreach (var r in rows) text.AppendLine(string.Join(',', new[] { r.Project, r.Repository, r.Application, r.Package,
            r.Ecosystem, r.Version, r.Kind.ToString(), r.Identity, r.Severity, r.Title, r.Assessment.ToString(),
            r.AcceptedUntil?.ToString("O"), r.CollectedAt.ToString("O"), r.AnalyzedAt?.ToString("O"), r.Coverage, r.SyncStatus }.Select(SafeInput.Csv)));
        return text.ToString();
    }
}
