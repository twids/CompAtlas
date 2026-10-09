using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using CompAtlas.Core;
using Microsoft.EntityFrameworkCore;

namespace CompAtlas.Infrastructure;

public sealed class ProjectAccess(AtlasDb db)
{
    public static string ActorSid(ClaimsPrincipal user) => user.FindFirstValue(ClaimTypes.PrimarySid)
        ?? user.FindFirstValue(ClaimTypes.NameIdentifier) ?? "unknown";
    public static string[] GroupSids(ClaimsPrincipal user) => user.Claims
        .Where(c => c.Type == ClaimTypes.GroupSid).Select(c => c.Value).Distinct().ToArray();
    private IQueryable<RoleBinding> Bindings(ClaimsPrincipal user)
    {
        var sids = GroupSids(user);
        return db.RoleBindings.Where(x => sids.Contains(x.GroupSid));
    }
    public async Task<bool> IsAdmin(ClaimsPrincipal user, CancellationToken ct = default) =>
        user.Identity?.IsAuthenticated == true && await Bindings(user).AnyAsync(x => x.Role == AccessRole.Administrator && x.ProjectId == null, ct);
    public async Task<Guid[]> ReadableProjects(ClaimsPrincipal user, CancellationToken ct = default)
    {
        if (user.Identity?.IsAuthenticated != true || user.HasClaim("atlas:machine", "true")) return [];
        var bindings = Bindings(user);
        if (await bindings.AnyAsync(x => x.Role == AccessRole.SecurityReader && x.ProjectId == null, ct))
            return await db.Projects.Select(x => x.Id).ToArrayAsync(ct);
        return await bindings.Where(x => x.ProjectId != null && (x.Role == AccessRole.ProjectReader || x.Role == AccessRole.ProjectReviewer))
            .Select(x => x.ProjectId!.Value).Distinct().ToArrayAsync(ct);
    }
    public async Task<bool> CanReview(ClaimsPrincipal user, Guid projectId, CancellationToken ct = default) =>
        user.Identity?.IsAuthenticated == true && !user.HasClaim("atlas:machine", "true") &&
        await Bindings(user).AnyAsync(x => x.ProjectId == projectId && x.Role == AccessRole.ProjectReviewer, ct);
    public static void ValidateBinding(RoleBinding binding)
    {
        if (!Regex.IsMatch(binding.GroupSid, @"^S-1-\d+(-\d+){1,15}$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)))
            throw new ArgumentException("A valid AD group SID is required.");
        if ((binding.Role is AccessRole.ProjectReader or AccessRole.ProjectReviewer) != binding.ProjectId.HasValue)
            throw new ArgumentException("Project roles require a project; global roles cannot be project scoped.");
        if (!Enum.IsDefined(binding.Role)) throw new ArgumentException("Unknown role.");
    }
}
public static class Secrets
{
    public static string Hash(string secret) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));
    public static string Create() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
}
public static class SafeInput
{
    public const int MaxBomBytes = 10 * 1024 * 1024;
    public static string Text(string value, int max, string label)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > max || value.Any(char.IsControl))
            throw new ArgumentException($"Invalid {label}.");
        return value;
    }
    public static string RelativePath(string path)
    {
        Text(path, 400, "application path");
        path = path.Replace('\\', '/');
        if (path.StartsWith('/') || path.Contains(':') || path.Split('/').Any(p => p is ".." or ""))
            throw new ArgumentException("Application path must be relative and cannot traverse directories.");
        return path;
    }
    public static Uri HttpsEndpoint(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != "https" ||
            !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
            throw new ArgumentException("An HTTPS endpoint without embedded credentials, query or fragment is required.");
        return uri;
    }
    public static string Csv(string? value)
    {
        value ??= "";
        if (value.TrimStart().FirstOrDefault() is '=' or '+' or '-' or '@' || value.StartsWith('\t') || value.StartsWith('\r')) value = "'" + value;
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }
}
