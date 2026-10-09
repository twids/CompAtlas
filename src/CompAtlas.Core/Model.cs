namespace CompAtlas.Core;

public enum AccessRole { ProjectReader, ProjectReviewer, SecurityReader, Administrator }
public enum JobKind { Discover, Collect, Analyze, ReviewSync, MalwareImport }
public enum JobState { Queued, Running, Completed, Failed }
public enum SnapshotState { Pending, Processing, Complete, Partial, Failed }
public enum FindingKind { Vulnerability, License, MaliciousPackage, EvidenceGap }
public enum Assessment { Unreviewed, InTriage, Exploitable, FalsePositive, NotAffected, Resolved }
public enum SyncState { Pending, Synchronized, Conflict, Failed, LocalOnly }

public sealed class SourceConnection
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "";
    public string BaseUrl { get; set; } = "";
    public string ApiVersion { get; set; } = "7.0";
    public bool Enabled { get; set; } = true;
    public DateTimeOffset? LastDiscovery { get; set; }
    public string? LastError { get; set; }
}
public sealed class SourceProject
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ConnectionId { get; set; }
    public Guid ExternalId { get; set; }
    public string Name { get; set; } = "";
    public string? Owner { get; set; }
}
public sealed class Repository
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ProjectId { get; set; }
    public Guid ExternalId { get; set; }
    public string Name { get; set; } = "";
    public string CloneUrl { get; set; } = "";
    public string DefaultBranch { get; set; } = "refs/heads/main";
    public string? HeadCommit { get; set; }
    public bool Enabled { get; set; } = true;
    public DateTimeOffset? LastSeen { get; set; }
}
public sealed class Application
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid RepositoryId { get; set; }
    public string Name { get; set; } = "";
    public string RelativePath { get; set; } = ".";
}
public sealed class Snapshot
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ApplicationId { get; set; }
    public string Commit { get; set; } = "";
    public string Branch { get; set; } = "";
    public string? BuildId { get; set; }
    public string? ReleaseId { get; set; }
    public bool IsDefaultBranch { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? AnalyzedAt { get; set; }
    public SnapshotState State { get; set; }
    public string BomJson { get; set; } = "";
    public string BomHash { get; set; } = "";
    public string SubmissionKey { get; set; } = "";
    public Guid? DependencyTrackId { get; set; }
    public string? ProcessingToken { get; set; }
    public string Coverage { get; set; } = "Not assessed";
    public string Traceability { get; set; } = "Not assessed";
    public string SignatureEvidence { get; set; } = "Not assessed";
    public string? LastError { get; set; }
}
public sealed class Component
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid SnapshotId { get; set; }
    public string BomRef { get; set; } = "";
    public string Ecosystem { get; set; } = "unknown";
    public string Name { get; set; } = "";
    public string? Version { get; set; }
    public string? Purl { get; set; }
    public string? License { get; set; }
    public string? Hash { get; set; }
    public string? Origin { get; set; }
    public string Confidence { get; set; } = "Declared";
    public bool? Direct { get; set; }
    public string DependencyRefsJson { get; set; } = "[]";
    public Guid? DependencyTrackId { get; set; }
}
public sealed class Finding
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid SnapshotId { get; set; }
    public Guid? ComponentId { get; set; }
    public FindingKind Kind { get; set; }
    public string Identity { get; set; } = "";
    public string AliasesJson { get; set; } = "[]";
    public string Title { get; set; } = "";
    public string Severity { get; set; } = "Unknown";
    public string? Detail { get; set; }
    public string? Recommendation { get; set; }
    public string? ExternalId { get; set; }
    public string? ExternalSource { get; set; }
    public string ExternalAssessmentJson { get; set; } = "{}";
    public DateTimeOffset ObservedAt { get; set; } = DateTimeOffset.UtcNow;
    public bool Active { get; set; } = true;
}
public sealed class Review
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid FindingId { get; set; }
    public Assessment Assessment { get; set; }
    public string Reason { get; set; } = "";
    public string ActorSid { get; set; } = "";
    public string ActorName { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? AcceptedUntil { get; set; }
    public DateTimeOffset? ExpiredAt { get; set; }
    public SyncState SyncState { get; set; }
    public string ExpectedExternalJson { get; set; } = "{}";
}
public sealed class RoleBinding
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string GroupSid { get; set; } = "";
    public AccessRole Role { get; set; }
    public Guid? ProjectId { get; set; }
}
public sealed class MachineCredential
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ProjectId { get; set; }
    public string Name { get; set; } = "";
    public string SecretHash { get; set; } = "";
    public DateTimeOffset ExpiresAt { get; set; }
    public bool CanCollect { get; set; }
    public bool Revoked { get; set; }
}
public sealed class Job
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public JobKind Kind { get; set; }
    public JobState State { get; set; }
    public Guid? ProjectId { get; set; }
    public Guid TargetId { get; set; }
    public string DedupeKey { get; set; } = "";
    public string Payload { get; set; } = "{}";
    public int Attempts { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset AvailableAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? LeaseUntil { get; set; }
    public Guid? LeaseOwner { get; set; }
    public Guid? CredentialId { get; set; }
    public string? LastError { get; set; }
    public long Revision { get; set; }
}
public sealed class AuditEvent
{
    public long Id { get; set; }
    public DateTimeOffset At { get; set; } = DateTimeOffset.UtcNow;
    public string ActorSid { get; set; } = "";
    public string Action { get; set; } = "";
    public Guid? ProjectId { get; set; }
    public string Target { get; set; } = "";
    public string Detail { get; set; } = "";
}
public sealed class IntelligenceSource
{
    public string Name { get; set; } = "";
    public DateTimeOffset? LastSuccess { get; set; }
    public string? LastError { get; set; }
    public int RecordCount { get; set; }
}
public sealed class MaliciousPackage
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string AdvisoryId { get; set; } = "";
    public string Ecosystem { get; set; } = "";
    public string Name { get; set; } = "";
    public string VersionsJson { get; set; } = "[]";
    public string RangesJson { get; set; } = "[]";
    public string Summary { get; set; } = "";
}
