using System.Text.RegularExpressions;
using NuGet.Versioning;

namespace CompAtlas.Infrastructure;

public static class VersionFilter
{
    public static Func<string?, bool> Parse(string ecosystem, string filter)
    {
        if (filter.StartsWith('=')) return version => version == filter[1..];
        if (ecosystem is "npm" or "nuget")
        {
            if (!VersionRange.TryParse(filter, out var range)) throw new ArgumentException("Use =version or an interval such as [1.0.0,2.0.0). Native npm expressions are not accepted.");
            return version => NuGetVersion.TryParse(version, out var parsed) && range.Satisfies(parsed);
        }
        if (ecosystem == "pypi")
        {
            var match = Regex.Match(filter, @"^(\[|\()([^,]*),([^\]\)]*)(\]|\))$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
            if (!match.Success) throw new ArgumentException("Use =version or a Python interval such as [1.0,2.0). Native requirement expressions are not accepted.");
            var lower = match.Groups[2].Value.Trim(); var upper = match.Groups[3].Value.Trim();
            if ((lower.Length > 0 && !PythonVersion.TryParse(lower, out _)) || (upper.Length > 0 && !PythonVersion.TryParse(upper, out _))) throw new ArgumentException("Unsupported Python version bound.");
            return version => PythonVersion.TryParse(version, out var parsed) &&
                (lower.Length == 0 || parsed.CompareTo(PythonVersion.Parse(lower)) is var l && (l > 0 || l == 0 && match.Groups[1].Value == "[")) &&
                (upper.Length == 0 || parsed.CompareTo(PythonVersion.Parse(upper)) is var u && (u < 0 || u == 0 && match.Groups[4].Value == "]"));
        }
        throw new ArgumentException("This ecosystem supports exact =version matching only.");
    }
    public static int? Compare(string ecosystem, string a, string b)
    {
        if (ecosystem == "pypi") return PythonVersion.TryParse(a, out var pa) && PythonVersion.TryParse(b, out var pb) ? pa.CompareTo(pb) : null;
        return NuGetVersion.TryParse(a, out var va) && NuGetVersion.TryParse(b, out var vb) ? va.CompareTo(vb) : null;
    }
}

// PEP 440 public-version ordering. Local versions require exact matching; no lexical version comparisons.
public sealed record PythonVersion(int Epoch, int[] Release, int PreKind, int Pre, int Post, int Dev) : IComparable<PythonVersion>
{
    private static readonly Regex Pattern = new(@"^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:(a|alpha|b|beta|rc|c|pre|preview)(\d*))?(?:[._-]?(post|rev|r)(\d*))?(?:[._-]?dev(\d*))?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    public static bool TryParse(string? value, out PythonVersion result)
    {
        result = null!;
        if (value == null || value.Length > 128) return false;
        var m = Pattern.Match(value);
        if (!m.Success) return false;
        try
        {
            int Number(string text, int fallback) => text.Length == 0 ? fallback : int.Parse(text, System.Globalization.CultureInfo.InvariantCulture);
            var pre = m.Groups[3].Value.ToLowerInvariant();
            var dev = m.Groups[7].Success ? Number(m.Groups[7].Value, 0) : int.MaxValue;
            var kind = pre switch { "a" or "alpha" => 0, "b" or "beta" => 1, "rc" or "c" or "pre" or "preview" => 2, _ => dev == int.MaxValue || m.Groups[5].Success ? 3 : -1 };
            result = new(Number(m.Groups[1].Value, 0), m.Groups[2].Value.Split('.').Select(int.Parse).ToArray(), kind,
                Number(m.Groups[4].Value, 0), m.Groups[5].Success ? Number(m.Groups[6].Value, 0) : -1, dev);
            return true;
        }
        catch (OverflowException) { return false; }
    }
    public static PythonVersion Parse(string value) => TryParse(value, out var result) ? result : throw new ArgumentException("Unsupported Python version.");
    public int CompareTo(PythonVersion? other)
    {
        if (other == null) return 1;
        var result = Epoch.CompareTo(other.Epoch); if (result != 0) return result;
        for (var i = 0; i < Math.Max(Release.Length, other.Release.Length); i++)
        { result = (i < Release.Length ? Release[i] : 0).CompareTo(i < other.Release.Length ? other.Release[i] : 0); if (result != 0) return result; }
        foreach (var pair in new[] { (PreKind, other.PreKind), (Pre, other.Pre), (Post, other.Post), (Dev, other.Dev) })
        { result = pair.Item1.CompareTo(pair.Item2); if (result != 0) return result; }
        return 0;
    }
}
