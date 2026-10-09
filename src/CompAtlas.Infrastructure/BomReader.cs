using System.Text;
using System.Text.Json;
using CompAtlas.Core;

namespace CompAtlas.Infrastructure;

public sealed record ParsedBom(List<Component> Components, List<string> Gaps);
public static class JsonFields
{
    public static string? Str(this JsonElement value, string name) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out var field) && field.ValueKind == JsonValueKind.String ? field.GetString() : null;
    public static JsonElement[] Items(this JsonElement value, string name) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out var field) && field.ValueKind == JsonValueKind.Array ? field.EnumerateArray().ToArray() : [];
    public static JsonElement Obj(this JsonElement value, string name) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out var field) ? field : default;
}
public static class BomReader
{
    public static ParsedBom Read(string json, Guid snapshotId)
    {
        if (Encoding.UTF8.GetByteCount(json) > SafeInput.MaxBomBytes) throw new ArgumentException("SBOM exceeds the 10 MiB limit.");
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 64 });
        var root = doc.RootElement;
        if (root.Str("bomFormat") != "CycloneDX" || root.Str("specVersion") is not ("1.4" or "1.5" or "1.6"))
            throw new ArgumentException("CycloneDX JSON 1.4, 1.5 or 1.6 is required.");
        var nodes = Flatten(root.Items("components")).Take(20001).ToArray();
        if (nodes.Length > 20000) throw new ArgumentException("SBOM exceeds 20,000 components.");
        var components = new List<Component>();
        var gaps = new List<string>();
        var rootRef = root.Obj("metadata").Obj("component").Str("bom-ref");
        var deps = new Dictionary<string, string[]>(StringComparer.Ordinal);
        foreach (var d in root.Items("dependencies"))
        {
            var reference = d.Str("ref");
            if (reference != null && !deps.TryAdd(reference, d.Items("dependsOn").Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToArray()))
                throw new ArgumentException("Duplicate dependency reference.");
        }
        if (root.Items("components").Length == 0) gaps.Add("No components identified; inventory completeness has not been established.");
        if (root.Items("properties").Any(p => p.Str("name") == "compatlas:partial" && p.Str("value") == "true"))
            gaps.Add("Collector reported partial coverage; a build-generated SBOM is required for complete dependency resolution.");
        var reachable = new HashSet<string>(StringComparer.Ordinal);
        var pending = new Stack<string>();
        if (rootRef != null) pending.Push(rootRef);
        while (pending.TryPop(out var current))
            if (reachable.Add(current) && deps.TryGetValue(current, out var children)) foreach (var child in children) pending.Push(child);
        var references = new HashSet<string>(StringComparer.Ordinal);
        foreach (var node in nodes)
        {
            var name = SafeInput.Text(node.Str("name") ?? "", 400, "component name");
            var group = node.Str("group");
            if (!string.IsNullOrEmpty(group)) name = SafeInput.Text(group + "/" + name, 400, "component name");
            var reference = SafeInput.Text(node.Str("bom-ref") ?? node.Str("purl") ?? name, 400, "component reference");
            if (!references.Add(reference)) throw new ArgumentException("Duplicate component reference.");
            var purl = node.Str("purl");
            if (purl?.Length > 2048) throw new ArgumentException("Package URL is too long.");
            foreach (var link in node.Items("externalReferences"))
                if (Uri.TryCreate(link.Str("url"), UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.UserInfo))
                    throw new ArgumentException("SBOM must not contain URLs with embedded credentials.");
            var ecosystem = purl?.StartsWith("pkg:nuget/", StringComparison.Ordinal) == true ? "nuget" :
                purl?.StartsWith("pkg:npm/", StringComparison.Ordinal) == true ? "npm" :
                purl?.StartsWith("pkg:pypi/", StringComparison.Ordinal) == true ? "pypi" :
                purl?.StartsWith("pkg:", StringComparison.Ordinal) == true ? purl[4..].Split('/')[0] : "unknown";
            if (ecosystem is "nuget" or "pypi") name = name.ToLowerInvariant();
            if (ecosystem == "pypi") name = System.Text.RegularExpressions.Regex.Replace(name, "[-_.]+", "-");
            var version = node.Str("version");
            if (version?.Length > 128) throw new ArgumentException("Component version is too long.");
            var licenses = node.Items("licenses").Select(l => l.Str("expression") ?? l.Obj("license").Str("id") ?? l.Obj("license").Str("name")).Where(l => l != null);
            var origin = node.Items("externalReferences").FirstOrDefault(x => x.Str("type") == "distribution").Str("url");
            var component = new Component
            {
                SnapshotId = snapshotId,
                BomRef = reference,
                Name = name,
                Version = version,
                Purl = purl,
                Ecosystem = ecosystem,
                License = string.Join("; ", licenses),
                Origin = origin,
                Hash = node.Items("hashes").FirstOrDefault(x => x.Str("alg") == "SHA-256").Str("content"),
                Direct = rootRef != null && deps.TryGetValue(rootRef, out var direct) ? direct.Contains(reference, StringComparer.Ordinal) ? true : reachable.Contains(reference) ? false : null : null,
                DependencyRefsJson = JsonSerializer.Serialize(deps.GetValueOrDefault(reference, []))
            };
            components.Add(component);
            component.Confidence = "Declared evidence: " + (node.Items("properties").FirstOrDefault(p => p.Str("name") == "compatlas:evidence").Str("value") ?? "Scanner declaration; not independently verified");
            if (version == null) gaps.Add($"Unknown version: {name}.");
            if (purl == null) gaps.Add($"Unknown package identity: {name}.");
            if (string.IsNullOrEmpty(component.License)) gaps.Add($"License requires review: {name}.");
            if (origin == null) gaps.Add($"Package origin not evidenced: {name}.");
        }
        if (deps.Values.SelectMany(x => x).Any(x => !references.Contains(x))) gaps.Add("Dependency graph contains unresolved component references.");
        return new(components, gaps);
    }
    private static IEnumerable<JsonElement> Flatten(IEnumerable<JsonElement> components)
    {
        foreach (var component in components)
        {
            yield return component;
            foreach (var nested in Flatten(component.Items("components"))) yield return nested;
        }
    }
}
