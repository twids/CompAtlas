using CompAtlas.Core;
using CompAtlas.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace CompAtlas.Worker;

public sealed class Orchestrator(IServiceScopeFactory scopes, IOptions<AtlasOptions> options, ILogger<Orchestrator> logger, TimeProvider clock) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Schedule(stoppingToken);
                await Task.WhenAll(Enumerable.Range(0, Math.Clamp(options.Value.ConcurrentJobs, 1, 8)).Select(_ => Process(stoppingToken)));
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
            catch (Exception ex) { logger.LogError("Orchestration failed ({Type}); retrying.", ex.GetType().Name); }
            await Task.Delay(TimeSpan.FromSeconds(15), clock, stoppingToken);
        }
    }
    private async Task Schedule(CancellationToken ct)
    {
        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AtlasDb>();
        var queue = scope.ServiceProvider.GetRequiredService<JobQueue>();
        var date = clock.GetUtcNow().AddHours(-Math.Clamp(options.Value.NightlyHourUtc, 0, 23)).ToString("yyyyMMdd");
        foreach (var c in await db.Connections.Where(c => c.Enabled).ToListAsync(ct))
            await queue.Enqueue(JobKind.Discover, c.Id, "discover:" + c.Id + ":" + date, ct: ct);
        var snapshots = await db.Snapshots.Where(s => s.State == SnapshotState.Complete || s.State == SnapshotState.Partial).ToListAsync(ct);
        foreach (var s in snapshots.Where(s => s.BuildId != null || s.ReleaseId != null || snapshots.Where(x => x.ApplicationId == s.ApplicationId && x.IsDefaultBranch).OrderByDescending(x => x.CreatedAt).FirstOrDefault()?.Id == s.Id))
            await queue.Enqueue(JobKind.Analyze, s.Id, "refresh:" + s.Id + ":" + date, ct: ct);
        await queue.Enqueue(JobKind.MalwareImport, Guid.Empty, "malware:" + date, ct: ct);
        await scope.ServiceProvider.GetRequiredService<ReviewService>().Expire(ct);
        await Retention(db, ct);
    }
    private async Task Process(CancellationToken ct)
    {
        await using var scope = scopes.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var db = services.GetRequiredService<AtlasDb>();
        var queue = services.GetRequiredService<JobQueue>();
        var job = await queue.Claim(false, null, null, ct);
        if (job == null) return;
        try
        {
            switch (job.Kind)
            {
                case JobKind.Discover: await services.GetRequiredService<Discovery>().Run(job.TargetId, ct); break;
                case JobKind.Analyze:
                    await services.GetRequiredService<Analysis>().Run(job.TargetId, ct);
                    await services.GetRequiredService<Malware>().Match(job.TargetId, ct); break;
                case JobKind.ReviewSync: await services.GetRequiredService<Analysis>().SyncReview(job.TargetId, ct); break;
                case JobKind.MalwareImport: await services.GetRequiredService<Malware>().Import(ct); break;
                default: throw new InvalidOperationException("Unsupported orchestration job.");
            }
            await queue.Finish(job, true, null, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            // Roll back all unsaved result mutations before recording a failed attempt.
            db.ChangeTracker.Clear();
            job = await db.Jobs.SingleAsync(j => j.Id == job.Id, ct);
            var error = "Job failed (" + ex.GetType().Name + "). Check configuration, connectivity and restricted worker diagnostics.";
            logger.LogWarning("Job {JobId} ({Kind}) failed ({Type}).", job.Id, job.Kind, ex.GetType().Name);
            if (job.Kind == JobKind.Analyze)
            {
                var snapshot = await db.Snapshots.FindAsync([job.TargetId], ct);
                if (snapshot != null) { snapshot.LastError = error; if (snapshot.AnalyzedAt == null && job.Attempts >= 3) snapshot.State = SnapshotState.Failed; }
            }
            if (job.Kind == JobKind.ReviewSync && job.Attempts >= 3)
            { var review = await db.Reviews.FindAsync([job.TargetId], ct); if (review != null) review.SyncState = SyncState.Failed; }
            if (job.Kind == JobKind.Discover)
            { var connection = await db.Connections.FindAsync([job.TargetId], ct); if (connection != null) connection.LastError = error; }
            if (job.Kind == JobKind.MalwareImport)
            {
                var source = await db.IntelligenceSources.FindAsync(["OpenSSF malicious-packages"], ct);
                if (source == null) { source = new IntelligenceSource { Name = "OpenSSF malicious-packages" }; db.IntelligenceSources.Add(source); }
                source.LastError = error;
            }
            await queue.Finish(job, false, error, ct);
        }
    }
    private async Task Retention(AtlasDb db, CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var all = await db.Snapshots.AsNoTracking().ToListAsync(ct);
        var protectedIds = all.Where(s => s.IsDefaultBranch).GroupBy(s => s.ApplicationId)
            .SelectMany(g => g.OrderByDescending(s => s.CreatedAt).Take(1).Concat(g.Where(s => s.State is SnapshotState.Complete or SnapshotState.Partial).OrderByDescending(s => s.CreatedAt).Take(1)))
            .Select(s => s.Id).ToHashSet();
        foreach (var s in all.Where(s => !protectedIds.Contains(s.Id) && s.CreatedAt < now.AddDays(-(s.BuildId != null || s.ReleaseId != null ? Math.Max(365, options.Value.ReleaseRetentionDays) : Math.Max(90, options.Value.SnapshotRetentionDays)))))
        {
            if (await db.Findings.AnyAsync(f => f.SnapshotId == s.Id && f.Active, ct)) continue;
            var ids = await db.Findings.Where(f => f.SnapshotId == s.Id).Select(f => f.Id).ToArrayAsync(ct);
            if (await db.Reviews.AnyAsync(r => ids.Contains(r.FindingId), ct)) continue;
            if (await db.Jobs.AnyAsync(j => j.TargetId == s.Id && (j.State == JobState.Queued || j.State == JobState.Running), ct)) continue;
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await db.Findings.Where(f => f.SnapshotId == s.Id).ExecuteDeleteAsync(ct);
            await db.Components.Where(c => c.SnapshotId == s.Id).ExecuteDeleteAsync(ct);
            await db.Snapshots.Where(x => x.Id == s.Id).ExecuteDeleteAsync(ct);
            await tx.CommitAsync(ct);
        }
        await db.Jobs.Where(j => (j.State == JobState.Completed || j.State == JobState.Failed) && j.CreatedAt < now.AddDays(-90)).ExecuteDeleteAsync(ct);
    }
}
