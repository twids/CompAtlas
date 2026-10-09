using CompAtlas.Core;
using CompAtlas.Infrastructure;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace CompAtlas.Web.Pages;

public sealed class IndexModel(Reports reports, AtlasDb db, ProjectAccess access, JobQueue queue) : PageModel
{
    public List<CoverageRow> Coverage { get; private set; } = [];
    public List<FindingRow> Findings { get; private set; } = [];
    public List<Snapshot> History { get; private set; } = [];
    public List<SourceProject> Projects { get; private set; } = [];
    [BindProperty(SupportsGet = true)] public Guid? Project { get; set; }
    [BindProperty(SupportsGet = true)] public Guid? Repository { get; set; }
    [BindProperty(SupportsGet = true)] public Guid? Snapshot { get; set; }
    public bool CanCollect { get; private set; }
    public async Task OnGetAsync(CancellationToken ct)
    {
        var allowed = await access.ReadableProjects(User, ct);
        Projects = await db.Projects.AsNoTracking().Where(p => allowed.Contains(p.Id)).OrderBy(p => p.Name).ToListAsync(ct);
        Coverage = (await reports.Coverage(User, ct)).Where(x => (Project == null || x.ProjectId == Project) && (Repository == null || x.RepositoryId == Repository)).ToList();
        Findings = await reports.Findings(User, Project, Repository, Snapshot, ct);
        if (Repository != null && Coverage.Count > 0)
        {
            var apps = await db.Applications.Where(a => a.RepositoryId == Repository).Select(a => a.Id).ToArrayAsync(ct);
            History = await db.Snapshots.AsNoTracking().Where(s => apps.Contains(s.ApplicationId)).OrderByDescending(s => s.CreatedAt).Take(100).ToListAsync(ct);
            CanCollect = await access.CanReview(User, Coverage[0].ProjectId, ct);
        }
    }
    public async Task<IActionResult> OnPostCollectAsync(Guid repository, CancellationToken ct)
    {
        var repo = await db.Repositories.SingleOrDefaultAsync(r => r.Id == repository, ct);
        if (repo == null || !await access.CanReview(User, repo.ProjectId, ct)) return NotFound();
        if (repo.HeadCommit == null) return BadRequest("Repository has no discovered commit.");
        await queue.Enqueue(JobKind.Collect, repo.Id, "manual:" + Guid.NewGuid(), repo.ProjectId,
            System.Text.Json.JsonSerializer.Serialize(new { Commit = repo.HeadCommit, Branch = repo.DefaultBranch }), ct);
        db.Audit.Add(new AuditEvent { ActorSid = ProjectAccess.ActorSid(User), Action = "CollectionRequested", ProjectId = repo.ProjectId, Target = repo.Id.ToString() });
        await db.SaveChangesAsync(ct);
        TempData["Message"] = "Collection queued. Previous successful results remain available.";
        return RedirectToPage(new { Repository = repository });
    }
}
