using CompAtlas.Core;
using CompAtlas.Infrastructure;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace CompAtlas.Web.Pages;

public sealed class OperationsModel(AtlasDb db, ProjectAccess access) : PageModel
{
    public List<Job> Jobs { get; private set; } = [];
    public List<IntelligenceSource> Sources { get; private set; } = [];
    public List<SourceConnection> Connections { get; private set; } = [];
    public async Task OnGetAsync(CancellationToken ct)
    {
        var projects = await access.ReadableProjects(User, ct);
        var admin = await access.IsAdmin(User, ct);
        Jobs = await db.Jobs.AsNoTracking().Where(j => admin || (j.ProjectId != null && projects.Contains(j.ProjectId.Value)))
            .OrderByDescending(j => j.CreatedAt).Take(200).ToListAsync(ct);
        if (admin || projects.Length > 0) Sources = await db.IntelligenceSources.AsNoTracking().ToListAsync(ct);
        if (admin) Connections = await db.Connections.AsNoTracking().ToListAsync(ct);
    }
}
