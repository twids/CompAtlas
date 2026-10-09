using System.Security.Cryptography;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace CompAtlas.Collector;

public sealed record InventoryComponent(string Name, string? Version, string? Purl, string? Hash, string Evidence);
public static class Inventory
{
    public static string Create(string directory)
    {
        var root = Path.GetFullPath(directory);
        if (!Directory.Exists(root) || (File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0) throw new ArgumentException("A real checkout directory is required.");
        var components = new List<InventoryComponent>();
        var files = Walk(root).Take(20001).ToArray();
        if (files.Length > 20000) throw new InvalidOperationException("Checkout exceeds conservative collector file limit; use a build-generated SBOM.");
        foreach (var file in files)
        {
            var name = Path.GetFileName(file);
            if (new FileInfo(file).Length > 20 * 1024 * 1024) continue;
            if (name == "package-lock.json") ReadNpm(file, components);
            else if (name is "packages.config" || name.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)) ReadNuGet(file, components);
            else if (name.StartsWith("requirements", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".txt", StringComparison.OrdinalIgnoreCase)) ReadPython(file, components);
            else if (name == "bower.json" || name == "package.json") ReadManifest(file, components);
            else if (name.EndsWith(".js", StringComparison.OrdinalIgnoreCase))
                components.Add(new InventoryComponent(Path.GetRelativePath(root, file).Replace('\\', '/'), null, null,
                    Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file))), "Unidentified JavaScript file; not inferred to be a third-party package"));
        }
        var deduped = components.DistinctBy(c => (c.Name, c.Version, c.Purl, c.Hash)).ToArray();
        return JsonSerializer.Serialize(new
        {
            bomFormat = "CycloneDX",
            specVersion = "1.6",
            serialNumber = "urn:uuid:" + Guid.NewGuid(),
            version = 1,
            metadata = new { timestamp = DateTimeOffset.UtcNow, component = new Dictionary<string, object> { ["type"] = "application", ["name"] = Path.GetFileName(root), ["bom-ref"] = "application" } },
            properties = new[] { new { name = "compatlas:partial", value = "true" }, new { name = "compatlas:collector", value = "conservative-file-inventory" } },
            components = deduped.Select((c, i) => new Dictionary<string, object?>
            {
                ["type"] = "library",
                ["bom-ref"] = "component-" + i,
                ["name"] = c.Name,
                ["version"] = c.Version,
                ["purl"] = c.Purl,
                ["hashes"] = c.Hash == null ? Array.Empty<object>() : new object[] { new { alg = "SHA-256", content = c.Hash } },
                ["properties"] = new[] { new { name = "compatlas:evidence", value = c.Evidence } }
            }).ToArray()
        }, new JsonSerializerOptions { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull });
    }
    private static IEnumerable<string> Walk(string directory)
    {
        foreach (var file in Directory.EnumerateFiles(directory)) if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) == 0) yield return file;
        foreach (var sub in Directory.EnumerateDirectories(directory))
        {
            if ((File.GetAttributes(sub) & FileAttributes.ReparsePoint) != 0 || Path.GetFileName(sub) is ".git" or "node_modules" or "bin" or "obj" or ".venv" or "venv") continue;
            foreach (var file in Walk(sub)) yield return file;
        }
    }
    private static void ReadNuGet(string file, List<InventoryComponent> result)
    {
        using var reader = XmlReader.Create(file, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 20 * 1024 * 1024 });
        var doc = XDocument.Load(reader);
        foreach (var p in doc.Descendants().Where(x => x.Name.LocalName is "package" or "PackageReference"))
        {
            var name = p.Attribute("id")?.Value ?? p.Attribute("Include")?.Value;
            if (name == null) continue;
            var version = p.Attribute("version")?.Value ?? p.Attribute("Version")?.Value ?? p.Elements().FirstOrDefault(x => x.Name.LocalName == "Version")?.Value;
            if (!Exact(version)) version = null;
            result.Add(new InventoryComponent(name.ToLowerInvariant(), version, Purl("nuget", name.ToLowerInvariant(), version), null, "Declared NuGet reference; restore not performed"));
        }
    }
    private static void ReadNpm(string file, List<InventoryComponent> result)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(file), new JsonDocumentOptions { MaxDepth = 64 });
        if (doc.RootElement.TryGetProperty("packages", out var packages))
            foreach (var p in packages.EnumerateObject())
            {
                if (p.Name.Length == 0) continue;
                var at = p.Name.LastIndexOf("node_modules/", StringComparison.Ordinal);
                var name = p.Value.TryGetProperty("name", out var n) ? n.GetString() : at >= 0 ? p.Name[(at + 13)..] : p.Name;
                var version = p.Value.TryGetProperty("version", out var v) ? v.GetString() : null;
                if (name != null) result.Add(new InventoryComponent(name, version, Purl("npm", name, version), null, "npm lockfile"));
            }
        else if (doc.RootElement.TryGetProperty("dependencies", out var dependencies)) ReadNpmDependencies(dependencies, result);
    }
    private static void ReadNpmDependencies(JsonElement dependencies, List<InventoryComponent> result)
    {
        foreach (var p in dependencies.EnumerateObject())
        {
            var version = p.Value.TryGetProperty("version", out var v) ? v.GetString() : null;
            result.Add(new InventoryComponent(p.Name, version, Purl("npm", p.Name, version), null, "npm v1 lockfile"));
            if (p.Value.TryGetProperty("dependencies", out var nested)) ReadNpmDependencies(nested, result);
        }
    }
    private static void ReadManifest(string file, List<InventoryComponent> result)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(file), new JsonDocumentOptions { MaxDepth = 32 });
        foreach (var field in new[] { "dependencies", "devDependencies" })
            if (doc.RootElement.TryGetProperty(field, out var deps)) foreach (var p in deps.EnumerateObject())
            {
                var version = p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() : null;
                if (!Exact(version)) version = null;
                var ecosystem = Path.GetFileName(file) == "bower.json" ? "bower" : "npm";
                if (result.Any(c => c.Name == p.Name && c.Purl?.StartsWith("pkg:npm/", StringComparison.Ordinal) == true)) continue;
                result.Add(new InventoryComponent(p.Name, version, Purl(ecosystem, p.Name, version), null, "Declared manifest reference; unresolved ranges remain unknown"));
            }
    }
    private static void ReadPython(string file, List<InventoryComponent> result)
    {
        foreach (var line in File.ReadLines(file))
        {
            var match = System.Text.RegularExpressions.Regex.Match(line, @"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([A-Za-z0-9_.!+-]+)\s*(?:;.*|#.*)?$");
            if (!match.Success) continue;
            var name = System.Text.RegularExpressions.Regex.Replace(match.Groups[1].Value.ToLowerInvariant(), "[-_.]+", "-");
            var version = match.Groups[2].Value;
            result.Add(new InventoryComponent(name, version, Purl("pypi", name, version), null, "Pinned requirement; environment markers not evaluated"));
        }
    }
    private static bool Exact(string? version) => version != null && System.Text.RegularExpressions.Regex.IsMatch(version, @"^\d+(\.\d+){0,3}([-+][A-Za-z0-9.-]+)?$");
    private static string? Purl(string ecosystem, string name, string? version) => version == null ? null : "pkg:" + ecosystem + "/" + string.Join('/', name.Split('/').Select(Uri.EscapeDataString)) + "@" + Uri.EscapeDataString(version);
}
