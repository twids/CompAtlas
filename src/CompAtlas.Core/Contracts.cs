namespace CompAtlas.Core;

public sealed record Submission(Guid RepositoryId, string Application, string RelativePath, string Commit,
    string Branch, string? BuildId, string? ReleaseId, string BomJson);
public sealed record ReviewRequest(Assessment Assessment, string Reason, DateTimeOffset? AcceptedUntil, Guid? PreviousReviewId);
public sealed record Receipt(Guid Id, string Status);
public sealed record CollectionClaim(Guid Id, Guid LeaseOwner, Guid RepositoryId, string CloneUrl, string Branch,
    string Commit, DateTimeOffset LeaseUntil);
public sealed record Completion(Guid LeaseOwner, bool Success);
public sealed record FindingRow(Guid FindingId, Guid ProjectId, string Project, Guid RepositoryId, string Repository,
    string Application, Guid SnapshotId, string Commit, string? Build, string? Release, string Package, string Ecosystem,
    string? Version, FindingKind Kind, string Identity, string Severity, string Title, string? Detail,
    Assessment Assessment, DateTimeOffset? AcceptedUntil, DateTimeOffset CollectedAt, DateTimeOffset? AnalyzedAt,
    string Coverage, string SyncStatus, string? License);
public sealed record PackageRow(Guid ProjectId, string Project, Guid RepositoryId, string Repository,
    string Application, Guid SnapshotId, string Ecosystem, string Package, string? Version, string? License,
    bool? Direct, string Confidence, string? Origin, DateTimeOffset CollectedAt, string Coverage);
public sealed record CoverageRow(Guid ProjectId, string Project, Guid RepositoryId, string Repository,
    Guid? SnapshotId, DateTimeOffset? CollectedAt, DateTimeOffset? AnalyzedAt, string Status, string Coverage,
    string Traceability, string SignatureEvidence);
