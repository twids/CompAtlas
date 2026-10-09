using System.Security.Claims;
using System.Text;
using System.Text.Json;
using CompAtlas.Core;
using CompAtlas.Infrastructure;
using Microsoft.EntityFrameworkCore;

namespace CompAtlas.Web;

public static class AtlasApi
{
    public static void MapAtlasApi(this WebApplication app)
    {
        var reports = app.MapGroup("/api/v1").RequireAuthorization("Interactive");
        reports.MapGet("/findings", async (Guid? project, Guid? repository, Guid? snapshot, ClaimsPrincipal user, Reports reports, CancellationToken ct) =>
            Results.Ok(await reports.Findings(user, project, repository, snapshot, ct)));
        reports.MapGet("/coverage", async (ClaimsPrincipal user, Reports reports, CancellationToken ct) => Results.Ok(await reports.Coverage(user, ct)));
        reports.MapPost("/collections", async (Guid repository, HttpContext context, AtlasDb db, ProjectAccess access, JobQueue queue, Microsoft.AspNetCore.Antiforgery.IAntiforgery antiforgery, CancellationToken ct) =>
        {
            await antiforgery.ValidateRequestAsync(context);
            var repo = await db.Repositories.SingleOrDefaultAsync(r => r.Id == repository && r.Enabled, ct);
            if (repo == null || !await access.CanReview(context.User, repo.ProjectId, ct)) return Results.NotFound();
            if (repo.HeadCommit == null) return Results.Problem("Discover the repository revision first.", statusCode: 409);
            var job = await queue.Enqueue(JobKind.Collect, repo.Id, "manual:" + Guid.NewGuid(), repo.ProjectId,
                JsonSerializer.Serialize(new { Commit = repo.HeadCommit, Branch = repo.DefaultBranch }), ct);
            db.Audit.Add(new AuditEvent { ActorSid = ProjectAccess.ActorSid(context.User), Action = "CollectionRequested", ProjectId = repo.ProjectId, Target = repo.Id.ToString() });
            await db.SaveChangesAsync(ct);
            return Results.Accepted("/api/v1/collections/" + job.Id, new Receipt(job.Id, job.State.ToString()));
        });
        reports.MapGet("/collections/{id:guid}", async (Guid id, ClaimsPrincipal user, ProjectAccess access, AtlasDb db, CancellationToken ct) =>
        {
            var projects = await access.ReadableProjects(user, ct);
            var job = await db.Jobs.AsNoTracking().Where(j => j.Id == id && j.Kind == JobKind.Collect && j.ProjectId != null && projects.Contains(j.ProjectId.Value))
                .Select(j => new { j.Id, Status = j.State.ToString(), j.Attempts, j.CreatedAt, j.LeaseUntil, j.LastError }).SingleOrDefaultAsync(ct);
            return job == null ? Results.NotFound() : Results.Ok(job);
        });
        reports.MapGet("/packages", async (string? ecosystem, string? name, string? version, Guid? repository, Guid? snapshot, ClaimsPrincipal user, Reports reports, CancellationToken ct) =>
        {
            try { return Results.Ok(await reports.Packages(user, ecosystem, name, version, repository, snapshot, ct)); }
            catch (ArgumentException ex) { return Results.Problem(ex.Message, statusCode: 400); }
        });
        reports.MapGet("/reports/findings.csv", async (Guid? project, Guid? repository, Guid? snapshot, ClaimsPrincipal user, Reports reports, CancellationToken ct) =>
            Results.File(Encoding.UTF8.GetBytes(Reports.Csv(await reports.Findings(user, project, repository, snapshot, ct))), "text/csv; charset=utf-8", "compatlas-findings.csv"));
        reports.MapPost("/findings/{id:guid}/reviews", async (Guid id, ReviewRequest request, HttpContext context, ReviewService reviews, Microsoft.AspNetCore.Antiforgery.IAntiforgery antiforgery, CancellationToken ct) =>
        {
            await antiforgery.ValidateRequestAsync(context);
            try { return Results.Ok(await reviews.Record(context.User, id, request, ct)); }
            catch (KeyNotFoundException) { return Results.NotFound(); }
            catch (UnauthorizedAccessException) { return Results.NotFound(); }
            catch (ArgumentException ex) { return Results.Problem(ex.Message, statusCode: 400); }
            catch (InvalidOperationException ex) { return Results.Problem(ex.Message, statusCode: 409); }
        });
        var machines = app.MapGroup("/api/v1").RequireAuthorization("Machine").RequireRateLimiting("machine");
        machines.MapPost("/sboms", async (Submission input, HttpContext context, SubmissionService service, CancellationToken ct) =>
        {
            try
            {
                var snapshot = await service.Submit(input, Guid.Parse(context.User.FindFirstValue("atlas:project")!), ct);
                return Results.Accepted("/api/v1/submissions/" + snapshot.Id, new Receipt(snapshot.Id, snapshot.State.ToString()));
            }
            catch (KeyNotFoundException) { return Results.NotFound(); }
            catch (ArgumentException ex) { return Results.Problem(ex.Message, statusCode: 400); }
            catch (JsonException) { return Results.Problem("Malformed CycloneDX JSON.", statusCode: 400); }
            catch (DbUpdateException) { return Results.Problem("Concurrent submission. Retry the identical request.", statusCode: 409); }
        });
        machines.MapGet("/submissions/{id:guid}", async (Guid id, ClaimsPrincipal user, AtlasDb db, CancellationToken ct) =>
        {
            var project = Guid.Parse(user.FindFirstValue("atlas:project")!);
            var result = await (from s in db.Snapshots
                                join a in db.Applications on s.ApplicationId equals a.Id
                                join r in db.Repositories on a.RepositoryId equals r.Id
                                where s.Id == id && r.ProjectId == project
                                select new { s.Id, Status = s.State.ToString(), s.CreatedAt, s.AnalyzedAt, s.Coverage }).SingleOrDefaultAsync(ct);
            return result == null ? Results.NotFound() : Results.Ok(result);
        });
        machines.MapPost("/collection/claim", async (ClaimsPrincipal user, JobQueue queue, AtlasDb db, CancellationToken ct) =>
        {
            if (!user.HasClaim("atlas:collect", "true")) return Results.Forbid();
            var project = Guid.Parse(user.FindFirstValue("atlas:project")!);
            var credential = Guid.Parse(user.FindFirstValue("atlas:credential")!);
            var job = await queue.Claim(true, project, credential, ct);
            if (job == null) return Results.NoContent();
            var repo = await db.Repositories.SingleAsync(r => r.Id == job.TargetId && r.ProjectId == project, ct);
            using var payload = JsonDocument.Parse(job.Payload);
            return Results.Ok(new CollectionClaim(job.Id, job.LeaseOwner!.Value, repo.Id, repo.CloneUrl,
                payload.RootElement.Str("Branch") ?? repo.DefaultBranch, payload.RootElement.Str("Commit") ?? repo.HeadCommit ?? "", job.LeaseUntil!.Value));
        });
        machines.MapPost("/collection/{id:guid}/complete", async (Guid id, Completion completion, ClaimsPrincipal user, JobQueue queue, AtlasDb db, TimeProvider clock, CancellationToken ct) =>
        {
            if (!user.HasClaim("atlas:collect", "true")) return Results.Forbid();
            var project = Guid.Parse(user.FindFirstValue("atlas:project")!);
            var credential = Guid.Parse(user.FindFirstValue("atlas:credential")!);
            var job = await db.Jobs.SingleOrDefaultAsync(j => j.Id == id && j.ProjectId == project && j.Kind == JobKind.Collect &&
                j.State == JobState.Running && j.CredentialId == credential && j.LeaseOwner == completion.LeaseOwner && j.LeaseUntil > clock.GetUtcNow(), ct);
            if (job == null) return Results.NotFound();
            if (completion.Success)
            {
                using var payload = JsonDocument.Parse(job.Payload);
                var commit = payload.RootElement.Str("Commit");
                var hasInventory = await (from s in db.Snapshots
                                          join a in db.Applications on s.ApplicationId equals a.Id
                                          where a.RepositoryId == job.TargetId && s.Commit == commit
                                          select s.Id).AnyAsync(ct);
                if (!hasInventory) return Results.Problem("A successful collection requires submitted inventory for the claimed revision.", statusCode: 409);
            }
            await queue.Finish(job, completion.Success, completion.Success ? null : "Collector reported failure; inspect restricted worker logs.", ct);
            return Results.NoContent();
        });
    }
}
