using System.Security.Claims;
using CompAtlas.Core;
using Microsoft.EntityFrameworkCore;

namespace CompAtlas.Infrastructure;

public sealed class ReviewService(AtlasDb db, ProjectAccess access, JobQueue queue, TimeProvider clock)
{
    public async Task<Review> Record(ClaimsPrincipal user, Guid findingId, ReviewRequest request, CancellationToken ct)
    {
        if (!Enum.IsDefined(request.Assessment)) throw new ArgumentException("Unknown assessment.");
        SafeInput.Text(request.Reason, 4000, "reason");
        var projectId = await (from f in db.Findings
                               join s in db.Snapshots on f.SnapshotId equals s.Id
                               join a in db.Applications on s.ApplicationId equals a.Id
                               join r in db.Repositories on a.RepositoryId equals r.Id
                               where f.Id == findingId
                               select (Guid?)r.ProjectId).SingleOrDefaultAsync(ct) ?? throw new KeyNotFoundException();
        if (!await access.CanReview(user, projectId, ct)) throw new UnauthorizedAccessException();
        if (request.AcceptedUntil is { } expiry && (expiry <= clock.GetUtcNow() || expiry > clock.GetUtcNow().AddDays(365)))
            throw new ArgumentException("Exception expiry must be in the future and within one year.");
        await using var tx = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, ct);
        var latest = await db.Reviews.Where(r => r.FindingId == findingId).OrderByDescending(r => r.CreatedAt).ThenByDescending(r => r.Id).FirstOrDefaultAsync(ct);
        if (latest?.Id != request.PreviousReviewId) throw new InvalidOperationException("The review changed. Reload before submitting.");
        var finding = await db.Findings.SingleAsync(f => f.Id == findingId, ct);
        var review = new Review
        {
            FindingId = findingId,
            Assessment = request.Assessment,
            Reason = request.Reason,
            ActorSid = ProjectAccess.ActorSid(user),
            ActorName = user.Identity?.Name ?? "Unknown",
            AcceptedUntil = request.AcceptedUntil?.ToUniversalTime(),
            ExpectedExternalJson = finding.ExternalAssessmentJson,
            CreatedAt = clock.GetUtcNow(),
            SyncState = finding.Kind == FindingKind.Vulnerability && finding.ExternalId != null ? SyncState.Pending : SyncState.LocalOnly
        };
        db.Reviews.Add(review);
        db.Audit.Add(new AuditEvent
        {
            ActorSid = review.ActorSid,
            ProjectId = projectId,
            Action = "ReviewRecorded",
            Target = review.Id.ToString(),
            Detail = $"Assessment={review.Assessment}; exception expiry={review.AcceptedUntil:O}"
        });
        await db.SaveChangesAsync(ct);
        if (review.SyncState == SyncState.Pending) await queue.Enqueue(JobKind.ReviewSync, review.Id, "review:" + review.Id, projectId, ct: ct);
        await tx.CommitAsync(ct);
        return review;
    }
    public async Task Expire(CancellationToken ct)
    {
        var expired = await db.Reviews.Where(r => r.AcceptedUntil <= clock.GetUtcNow() && r.ExpiredAt == null).ToListAsync(ct);
        foreach (var review in expired)
        {
            review.ExpiredAt = clock.GetUtcNow();
            db.Audit.Add(new AuditEvent { ActorSid = "system", Action = "ExceptionExpired", Target = review.Id.ToString() });
        }
        await db.SaveChangesAsync(ct);
    }
}
