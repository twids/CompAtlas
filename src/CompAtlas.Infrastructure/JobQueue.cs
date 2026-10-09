using CompAtlas.Core;
using Microsoft.EntityFrameworkCore;

namespace CompAtlas.Infrastructure;

public sealed class JobQueue(AtlasDb db, TimeProvider clock, Microsoft.Extensions.Options.IOptions<AtlasOptions>? options = null)
{
    public async Task<Job> Enqueue(JobKind kind, Guid target, string key, Guid? project = null, string payload = "{}", CancellationToken ct = default)
    {
        var existing = await db.Jobs.SingleOrDefaultAsync(j => j.DedupeKey == key, ct);
        if (existing != null) return existing;
        var job = new Job
        {
            Kind = kind,
            TargetId = target,
            DedupeKey = key,
            ProjectId = project,
            Payload = payload,
            CreatedAt = clock.GetUtcNow(),
            AvailableAt = clock.GetUtcNow()
        };
        db.Jobs.Add(job);
        await db.SaveChangesAsync(ct);
        return job;
    }
    public async Task<Job?> Claim(bool collector, Guid? project, Guid? credentialId, CancellationToken ct)
    {
        // Serialize collector capacity decisions across service instances using a SQL Server application lock.
        await using var capacity = collector ? await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, ct) : null;
        if (collector && db.Database.IsSqlServer())
            await db.Database.ExecuteSqlRawAsync("DECLARE @result int; EXEC @result = sys.sp_getapplock @Resource=N'CompAtlas.CollectorCapacity', @LockMode=N'Exclusive', @LockOwner=N'Transaction', @LockTimeout=10000; IF @result < 0 THROW 50002, 'Collector capacity lock unavailable.', 1;", ct);
        if (collector && await db.Jobs.CountAsync(j => j.Kind == JobKind.Collect && j.State == JobState.Running && j.LeaseUntil > clock.GetUtcNow(), ct) >= Math.Clamp(options?.Value.ConcurrentJobs ?? 2, 1, 8)) return null;
        for (var retry = 0; retry < 5; retry++)
        {
            var now = clock.GetUtcNow();
            // A crashed worker's final attempt must become visible as failed rather than stay leased forever.
            await db.Jobs.Where(j => j.State == JobState.Running && j.LeaseUntil < now && j.Attempts >= 3)
                .ExecuteUpdateAsync(s => s.SetProperty(j => j.State, JobState.Failed).SetProperty(j => j.LeaseOwner, (Guid?)null)
                    .SetProperty(j => j.Revision, j => j.Revision + 1).SetProperty(j => j.LastError, "Lease expired after final attempt."), ct);
            var query = db.Jobs.Where(j => j.Attempts < 3 && j.AvailableAt <= now &&
                (j.State == JobState.Queued || (j.State == JobState.Running && j.LeaseUntil < now)));
            query = collector ? query.Where(j => j.Kind == JobKind.Collect && j.ProjectId == project)
                : query.Where(j => j.Kind != JobKind.Collect);
            var job = await query.OrderBy(j => j.CreatedAt).FirstOrDefaultAsync(ct);
            if (job == null) { if (capacity != null) await capacity.CommitAsync(ct); return null; }
            job.State = JobState.Running;
            job.Attempts++;
            job.LeaseOwner = Guid.NewGuid();
            job.LeaseUntil = now.AddMinutes(30);
            job.CredentialId = credentialId;
            job.Revision++;
            try { await db.SaveChangesAsync(ct); if (capacity != null) await capacity.CommitAsync(ct); return job; }
            catch (DbUpdateConcurrencyException) { db.ChangeTracker.Clear(); }
        }
        return null;
    }
    public async Task Finish(Job job, bool success, string? error, CancellationToken ct)
    {
        if (job.State != JobState.Running || job.LeaseUntil <= clock.GetUtcNow()) throw new InvalidOperationException("An active job lease is required.");
        job.State = success ? JobState.Completed : job.Attempts >= 3 ? JobState.Failed : JobState.Queued;
        job.LastError = error;
        job.AvailableAt = clock.GetUtcNow().AddMinutes(Math.Pow(2, job.Attempts));
        job.LeaseOwner = null;
        job.LeaseUntil = null;
        job.Revision++;
        await db.SaveChangesAsync(ct);
    }
}
