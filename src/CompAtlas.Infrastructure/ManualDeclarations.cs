using System.Security.Claims;
using System.Text.Json.Nodes;
using CompAtlas.Core;
using Microsoft.EntityFrameworkCore;

namespace CompAtlas.Infrastructure;

public sealed record ManualDeclarationRequest(Guid SnapshotId, string BomRef, string Name, string Version, string Ecosystem, string? License, string Reason);
public sealed class ManualDeclarations(AtlasDb db, ProjectAccess access, SubmissionService submissions)
{
    public async Task<Snapshot> Record(ClaimsPrincipal user, ManualDeclarationRequest request, CancellationToken ct)
    {
        var source = await db.Snapshots.SingleOrDefaultAsync(s => s.Id == request.SnapshotId, ct) ?? throw new KeyNotFoundException();
        var app = await db.Applications.SingleAsync(a => a.Id == source.ApplicationId, ct);
        var repo = await db.Repositories.SingleAsync(r => r.Id == app.RepositoryId, ct);
        if (!await access.CanReview(user, repo.ProjectId, ct)) throw new KeyNotFoundException();
        SafeInput.Text(request.Name, 400, "package name"); SafeInput.Text(request.Version, 128, "package version");
        SafeInput.Text(request.Reason, 4000, "declaration reason");
        if (request.Ecosystem is not ("npm" or "nuget" or "pypi")) throw new ArgumentException("Select NuGet, npm or PyPI.");
        if (request.License != null) SafeInput.Text(request.License, 200, "license declaration");
        var component = await db.Components.SingleOrDefaultAsync(c => c.SnapshotId == source.Id && c.BomRef == request.BomRef, ct) ?? throw new KeyNotFoundException();
        if (component.Hash == null) throw new ArgumentException("Manual file identification requires recorded SHA-256 evidence.");
        var root = JsonNode.Parse(source.BomJson)!.AsObject();
        var node = root["components"]!.AsArray().FirstOrDefault(c => c?["bom-ref"]?.GetValue<string>() == component.BomRef)?.AsObject() ?? throw new ArgumentException("Component evidence could not be located in the source SBOM.");
        node["name"] = request.Name; node.Remove("group"); node["version"] = request.Version;
        node["purl"] = "pkg:" + request.Ecosystem + "/" + string.Join('/', request.Name.Split('/').Select(Uri.EscapeDataString)) + "@" + Uri.EscapeDataString(request.Version);
        if (request.License != null) node["licenses"] = new JsonArray(new JsonObject { ["expression"] = request.License });
        node["properties"] = new JsonArray(new JsonObject { ["name"] = "compatlas:evidence", ["value"] = "Manually identified from file hash; reviewed by " + ProjectAccess.ActorSid(user) },
            new JsonObject { ["name"] = "compatlas:declaration-reason", ["value"] = request.Reason });
        // Preserve the original BOM and release snapshot; create a separate derived analysis.
        var derived = await submissions.Submit(new Submission(repo.Id, app.Name, app.RelativePath, source.Commit, source.Branch, source.BuildId, source.ReleaseId, root.ToJsonString()), repo.ProjectId, ct);
        var declared = await db.Components.SingleAsync(c => c.SnapshotId == derived.Id && c.BomRef == component.BomRef, ct);
        declared.Confidence = "Manually reviewed in CompAtlas by " + ProjectAccess.ActorSid(user);
        db.Audit.Add(new AuditEvent { ActorSid = ProjectAccess.ActorSid(user), ProjectId = repo.ProjectId, Action = "ManualComponentDeclared", Target = derived.Id.ToString(), Detail = "Source snapshot=" + source.Id + "; evidence hash=" + component.Hash });
        await db.SaveChangesAsync(ct);
        return derived;
    }
}
