using CompAtlas.Core;
using CompAtlas.Infrastructure;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace CompAtlas.Web.Pages;

public sealed class PackagesModel(Reports reports) : PageModel
{
    [BindProperty(SupportsGet = true)] public string? Ecosystem { get; set; }
    [BindProperty(SupportsGet = true)] public string? Name { get; set; }
    [BindProperty(SupportsGet = true)] public string? Version { get; set; }
    [BindProperty(SupportsGet = true)] public Guid? Repository { get; set; }
    [BindProperty(SupportsGet = true)] public Guid? Snapshot { get; set; }
    public List<PackageRow> Results { get; private set; } = [];
    public async Task<IActionResult> OnGetAsync(bool export, CancellationToken ct)
    {
        try { Results = await reports.Packages(User, Empty(Ecosystem), Empty(Name), Empty(Version), Repository, Snapshot, ct); }
        catch (ArgumentException ex) { ModelState.AddModelError("", ex.Message); }
        if (export && ModelState.IsValid)
        {
            var csv = "Project,Repository,Application,Ecosystem,Package,Version,License,Direct,Confidence,CollectedAt,Coverage\r\n" +
                string.Join("\r\n", Results.Select(r => string.Join(',', new[] { r.Project, r.Repository, r.Application, r.Ecosystem,
                    r.Package, r.Version, r.License, r.Direct?.ToString() ?? "Unknown", r.Confidence, r.CollectedAt.ToString("O"), r.Coverage }.Select(SafeInput.Csv))));
            return File(System.Text.Encoding.UTF8.GetBytes(csv), "text/csv; charset=utf-8", "compatlas-packages.csv");
        }
        return Page();
    }
    private static string? Empty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
