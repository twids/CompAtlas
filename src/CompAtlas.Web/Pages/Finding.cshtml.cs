using System.ComponentModel.DataAnnotations;
using CompAtlas.Core;
using CompAtlas.Infrastructure;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace CompAtlas.Web.Pages;

public sealed class FindingModel(AtlasDb db, Reports reports, ProjectAccess access, ReviewService reviews, ManualDeclarations declarations) : PageModel
{
    public FindingRow? Finding { get; private set; }
    public List<Review> History { get; private set; } = [];
    public Component? Component { get; private set; }
    public List<Component> Dependencies { get; private set; } = [];
    public bool CanReview { get; private set; }
    public string? Recommendation { get; private set; }
    [BindProperty] public Assessment Assessment { get; set; }
    [BindProperty, Required, StringLength(4000)] public string Reason { get; set; } = "";
    [BindProperty] public bool AcceptRisk { get; set; }
    [BindProperty] public DateTimeOffset? AcceptedUntil { get; set; } = DateTimeOffset.UtcNow.AddDays(30);
    [BindProperty] public Guid? PreviousReviewId { get; set; }
    [BindProperty] public string PackageName { get; set; } = "";
    [BindProperty] public string PackageVersion { get; set; } = "";
    [BindProperty] public string Ecosystem { get; set; } = "npm";
    [BindProperty] public string? DeclaredLicense { get; set; }
    private async Task<bool> Load(Guid id, CancellationToken ct)
    {
        var snapshotId = await db.Findings.Where(f => f.Id == id).Select(f => (Guid?)f.SnapshotId).SingleOrDefaultAsync(ct);
        if (snapshotId == null) return false;
        Finding = (await reports.Findings(User, snapshot: snapshotId, ct: ct)).SingleOrDefault(f => f.FindingId == id);
        if (Finding == null) return false;
        Recommendation = await db.Findings.Where(f => f.Id == id).Select(f => f.Recommendation).SingleAsync(ct);
        History = await db.Reviews.AsNoTracking().Where(r => r.FindingId == id).OrderByDescending(r => r.CreatedAt).ThenByDescending(r => r.Id).ToListAsync(ct);
        CanReview = await access.CanReview(User, Finding.ProjectId, ct);
        var componentId = await db.Findings.Where(f => f.Id == id).Select(f => f.ComponentId).SingleAsync(ct);
        Component = await db.Components.AsNoTracking().SingleOrDefaultAsync(c => c.Id == componentId, ct);
        if (Component != null)
        {
            var refs = System.Text.Json.JsonSerializer.Deserialize<string[]>(Component.DependencyRefsJson) ?? [];
            Dependencies = await db.Components.AsNoTracking().Where(c => c.SnapshotId == snapshotId && refs.Contains(c.BomRef)).ToListAsync(ct);
        }
        return true;
    }
    public async Task<IActionResult> OnGetAsync(Guid id, CancellationToken ct)
    {
        if (!await Load(id, ct)) return NotFound();
        PreviousReviewId = History.FirstOrDefault()?.Id;
        Assessment = History.FirstOrDefault()?.Assessment ?? Assessment.Unreviewed;
        return Page();
    }
    public async Task<IActionResult> OnPostAsync(Guid id, CancellationToken ct)
    {
        if (!await Load(id, ct) || !CanReview) return NotFound();
        if (AcceptRisk && AcceptedUntil == null) ModelState.AddModelError(nameof(AcceptedUntil), "Expiry is required for risk acceptance.");
        if (!ModelState.IsValid) return Page();
        try { await reviews.Record(User, id, new ReviewRequest(Assessment, Reason, AcceptRisk ? AcceptedUntil : null, PreviousReviewId), ct); }
        catch (ArgumentException ex) { ModelState.AddModelError("", ex.Message); return Page(); }
        catch (InvalidOperationException ex) { ModelState.AddModelError("", ex.Message); return Page(); }
        TempData["Message"] = "Review recorded. Accepted risks remain visible.";
        return RedirectToPage(new { id });
    }
    public async Task<IActionResult> OnPostDeclareAsync(Guid id, CancellationToken ct)
    {
        if (!await Load(id, ct) || !CanReview || Component?.Hash == null) return NotFound();
        try
        {
            var snapshot = await declarations.Record(User, new ManualDeclarationRequest(Finding!.SnapshotId, Component.BomRef,
                PackageName, PackageVersion, Ecosystem, DeclaredLicense, Reason), ct);
            TempData["Message"] = "Manual declaration recorded in a new analysis snapshot. Original evidence was preserved.";
            return RedirectToPage("/Index", new { Repository = Finding.RepositoryId, Snapshot = snapshot.Id });
        }
        catch (ArgumentException ex) { ModelState.AddModelError("", ex.Message); return Page(); }
    }
}
