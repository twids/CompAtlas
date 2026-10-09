using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace CompAtlas.Tests;

public sealed class PreviewTests(AtlasFactory factory) : IClassFixture<AtlasFactory>
{
    [Fact]
    public async Task Capture_rendered_pages_for_browser_accessibility_checks()
    {
        var directory = Environment.GetEnvironmentVariable("COMPATLAS_PREVIEW_OUTPUT");
        if (string.IsNullOrWhiteSpace(directory)) return;
        Directory.CreateDirectory(directory);
        var web = Path.Combine(AppContext.BaseDirectory, "../../../../../src/CompAtlas.Web");
        File.Copy(Path.GetFullPath(Path.Combine(web, "wwwroot/site.css")), Path.Combine(directory, "site.css"), true);
        foreach (var page in new[] {("index","/","S-1-5-21-100"),("packages","/Packages","S-1-5-21-100"),
            ("operations","/Operations","S-1-5-21-100"),("administration","/Administration","S-1-5-21-300"),
            ("finding","/Finding/"+factory.Data.Finding.Id,"S-1-5-21-200")})
        {
            using var client = factory.Client(page.Item3);
            var response = await client.GetAsync(page.Item2); response.EnsureSuccessStatusCode();
            await File.WriteAllTextAsync(Path.Combine(directory, page.Item1 + ".html"), await response.Content.ReadAsStringAsync());
        }
    }
}
