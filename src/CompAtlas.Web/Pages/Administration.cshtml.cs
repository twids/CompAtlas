using CompAtlas.Core;
using CompAtlas.Infrastructure;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace CompAtlas.Web.Pages;

public sealed class AdministrationModel(AtlasDb db, ProjectAccess access, JobQueue queue, IConfiguration configuration) : PageModel
{
    public List<SourceProject> Projects { get; private set; } = [];
    public List<RoleBinding> Bindings { get; private set; } = [];
    public List<SourceConnection> Connections { get; private set; } = [];
    public List<MachineCredential> Credentials { get; private set; } = [];
    public string? IssuedSecret { get; private set; }
    [BindProperty] public string GroupSid { get; set; } = "";
    [BindProperty] public AccessRole Role { get; set; }
    [BindProperty] public Guid? ProjectId { get; set; }
    [BindProperty] public string Name { get; set; } = "";
    [BindProperty] public string BaseUrl { get; set; } = "";
    [BindProperty] public bool CanCollect { get; set; }
    private async Task Load(CancellationToken ct)
    {
        Projects = await db.Projects.OrderBy(p => p.Name).ToListAsync(ct);
        Bindings = await db.RoleBindings.AsNoTracking().ToListAsync(ct);
        Connections = await db.Connections.AsNoTracking().ToListAsync(ct);
        Credentials = await db.MachineCredentials.AsNoTracking().ToListAsync(ct);
    }
    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        if (!await access.IsAdmin(User, ct)) return NotFound();
        await Load(ct); return Page();
    }
    public async Task<IActionResult> OnPostRoleAsync(CancellationToken ct)
    {
        if (!await access.IsAdmin(User, ct)) return NotFound();
        var binding = new RoleBinding { GroupSid = GroupSid, Role = Role, ProjectId = ProjectId };
        try { ProjectAccess.ValidateBinding(binding); }
        catch (ArgumentException ex) { ModelState.AddModelError("", ex.Message); await Load(ct); return Page(); }
        if (ProjectId.HasValue && !await db.Projects.AnyAsync(p => p.Id == ProjectId, ct)) return BadRequest();
        db.RoleBindings.Add(binding);
        Audit("RoleGranted", binding.Id, $"Group={binding.GroupSid}; role={binding.Role}; project={ProjectId}");
        await db.SaveChangesAsync(ct); return RedirectToPage();
    }
    public async Task<IActionResult> OnPostRevokeRoleAsync(Guid id, CancellationToken ct)
    {
        if (!await access.IsAdmin(User, ct)) return NotFound();
        var binding = await db.RoleBindings.FindAsync([id], ct);
        if (binding == null) return NotFound();
        if (binding.Role == AccessRole.Administrator && await db.RoleBindings.CountAsync(b => b.Role == AccessRole.Administrator, ct) <= 1)
        { ModelState.AddModelError("", "The last administrator binding cannot be revoked."); await Load(ct); return Page(); }
        db.RoleBindings.Remove(binding); Audit("RoleRevoked", id, binding.Role.ToString());
        await db.SaveChangesAsync(ct); return RedirectToPage();
    }
    public async Task<IActionResult> OnPostConnectionAsync(CancellationToken ct)
    {
        if (!await access.IsAdmin(User, ct)) return NotFound();
        try
        {
            SafeInput.Text(Name, 200, "connection name");
            var uri = SafeInput.HttpsEndpoint(BaseUrl);
            var allowed = configuration.GetSection("CompAtlas:AllowedAzureHosts").Get<string[]>() ?? [];
            if (!allowed.Contains(uri.IdnHost, StringComparer.OrdinalIgnoreCase)) throw new ArgumentException("Collection host must first be provisioned in CompAtlas:AllowedAzureHosts by the operator.");
            var connection = new SourceConnection { Name = Name, BaseUrl = uri.AbsoluteUri.TrimEnd('/') + "/" };
            db.Connections.Add(connection); Audit("ConnectionCreated", connection.Id, connection.Name);
            await db.SaveChangesAsync(ct);
            await queue.Enqueue(JobKind.Discover, connection.Id, "discover:setup:" + connection.Id, ct: ct);
            return RedirectToPage();
        }
        catch (ArgumentException ex) { ModelState.AddModelError("", ex.Message); await Load(ct); return Page(); }
    }
    public async Task<IActionResult> OnPostCredentialAsync(CancellationToken ct)
    {
        if (!await access.IsAdmin(User, ct)) return NotFound();
        if (ProjectId == null || !await db.Projects.AnyAsync(p => p.Id == ProjectId, ct)) return BadRequest();
        try { SafeInput.Text(Name, 200, "credential name"); }
        catch (ArgumentException ex) { ModelState.AddModelError("", ex.Message); await Load(ct); return Page(); }
        IssuedSecret = Secrets.Create();
        var credential = new MachineCredential
        {
            ProjectId = ProjectId.Value,
            Name = Name,
            CanCollect = CanCollect,
            SecretHash = Secrets.Hash(IssuedSecret),
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(90)
        };
        db.MachineCredentials.Add(credential); Audit("MachineCredentialIssued", credential.Id, $"Project={ProjectId}; collection={CanCollect}");
        await db.SaveChangesAsync(ct); await Load(ct); return Page();
    }
    public async Task<IActionResult> OnPostRevokeCredentialAsync(Guid id, CancellationToken ct)
    {
        if (!await access.IsAdmin(User, ct)) return NotFound();
        var credential = await db.MachineCredentials.FindAsync([id], ct);
        if (credential == null) return NotFound();
        credential.Revoked = true; Audit("MachineCredentialRevoked", id, "");
        await db.SaveChangesAsync(ct); return RedirectToPage();
    }
    public async Task<IActionResult> OnPostDiscoverAsync(Guid id, CancellationToken ct)
    {
        if (!await access.IsAdmin(User, ct)) return NotFound();
        if (!await db.Connections.AnyAsync(c => c.Id == id, ct)) return NotFound();
        await queue.Enqueue(JobKind.Discover, id, "discover:manual:" + Guid.NewGuid(), ct: ct);
        Audit("DiscoveryRequested", id, ""); await db.SaveChangesAsync(ct); return RedirectToPage();
    }
    private void Audit(string action, Guid id, string detail) => db.Audit.Add(new AuditEvent
    {
        ActorSid = ProjectAccess.ActorSid(User),
        Action = action,
        Target = id.ToString(),
        Detail = detail
    });
}
