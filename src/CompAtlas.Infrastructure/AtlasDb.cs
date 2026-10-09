using CompAtlas.Core;
using Microsoft.EntityFrameworkCore;

namespace CompAtlas.Infrastructure;

public sealed class AtlasDb(DbContextOptions<AtlasDb> options) : DbContext(options)
{
    protected override void ConfigureConventions(ModelConfigurationBuilder b) =>
        b.Properties<DateTimeOffset>().HaveConversion<Microsoft.EntityFrameworkCore.Storage.ValueConversion.DateTimeOffsetToBinaryConverter>();
    public DbSet<SourceConnection> Connections => Set<SourceConnection>();
    public DbSet<SourceProject> Projects => Set<SourceProject>();
    public DbSet<Repository> Repositories => Set<Repository>();
    public DbSet<Application> Applications => Set<Application>();
    public DbSet<Snapshot> Snapshots => Set<Snapshot>();
    public DbSet<Component> Components => Set<Component>();
    public DbSet<Finding> Findings => Set<Finding>();
    public DbSet<Review> Reviews => Set<Review>();
    public DbSet<RoleBinding> RoleBindings => Set<RoleBinding>();
    public DbSet<MachineCredential> MachineCredentials => Set<MachineCredential>();
    public DbSet<Job> Jobs => Set<Job>();
    public DbSet<AuditEvent> Audit => Set<AuditEvent>();
    public DbSet<IntelligenceSource> IntelligenceSources => Set<IntelligenceSource>();
    public DbSet<MaliciousPackage> MaliciousPackages => Set<MaliciousPackage>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<SourceProject>().HasIndex(x => new { x.ConnectionId, x.ExternalId }).IsUnique();
        b.Entity<Repository>().HasIndex(x => new { x.ProjectId, x.ExternalId }).IsUnique();
        b.Entity<Application>().HasIndex(x => new { x.RepositoryId, x.RelativePath }).IsUnique();
        b.Entity<Application>().Property(x => x.RelativePath).HasMaxLength(400);
        b.Entity<Snapshot>().HasIndex(x => x.SubmissionKey).IsUnique();
        b.Entity<Snapshot>().Property(x => x.SubmissionKey).HasMaxLength(64);
        b.Entity<Component>().HasIndex(x => new { x.SnapshotId, x.BomRef }).IsUnique();
        b.Entity<Component>().Property(x => x.BomRef).HasMaxLength(400);
        b.Entity<Component>().HasIndex(x => new { x.Ecosystem, x.Name, x.Version });
        b.Entity<Component>().Property(x => x.Ecosystem).HasMaxLength(32);
        b.Entity<Component>().Property(x => x.Name).HasMaxLength(400);
        b.Entity<Component>().Property(x => x.Version).HasMaxLength(128);
        b.Entity<Finding>().HasIndex(x => new { x.SnapshotId, x.Identity }).IsUnique();
        b.Entity<Finding>().Property(x => x.Identity).HasMaxLength(400);
        b.Entity<Review>().HasIndex(x => new { x.FindingId, x.CreatedAt });
        b.Entity<RoleBinding>().Property(x => x.GroupSid).HasMaxLength(184);
        b.Entity<MachineCredential>().HasIndex(x => x.SecretHash).IsUnique();
        b.Entity<MachineCredential>().Property(x => x.SecretHash).HasMaxLength(64);
        b.Entity<Job>().HasIndex(x => x.DedupeKey).IsUnique();
        b.Entity<Job>().Property(x => x.DedupeKey).HasMaxLength(200);
        b.Entity<Job>().Property(x => x.Revision).IsConcurrencyToken();
        b.Entity<Job>().HasIndex(x => new { x.State, x.AvailableAt });
        b.Entity<IntelligenceSource>().HasKey(x => x.Name);
        b.Entity<IntelligenceSource>().Property(x => x.Name).HasMaxLength(100);
        b.Entity<MaliciousPackage>().HasIndex(x => new { x.AdvisoryId, x.Ecosystem, x.Name }).IsUnique();
        b.Entity<MaliciousPackage>().Property(x => x.AdvisoryId).HasMaxLength(100);
        b.Entity<MaliciousPackage>().Property(x => x.Ecosystem).HasMaxLength(32);
        b.Entity<MaliciousPackage>().Property(x => x.Name).HasMaxLength(400);
        b.Entity<SourceProject>().HasOne<SourceConnection>().WithMany().HasForeignKey(x => x.ConnectionId).OnDelete(DeleteBehavior.Restrict);
        b.Entity<Repository>().HasOne<SourceProject>().WithMany().HasForeignKey(x => x.ProjectId).OnDelete(DeleteBehavior.Restrict);
        b.Entity<Application>().HasOne<Repository>().WithMany().HasForeignKey(x => x.RepositoryId).OnDelete(DeleteBehavior.Restrict);
        b.Entity<Snapshot>().HasOne<Application>().WithMany().HasForeignKey(x => x.ApplicationId).OnDelete(DeleteBehavior.Restrict);
        b.Entity<Component>().HasOne<Snapshot>().WithMany().HasForeignKey(x => x.SnapshotId).OnDelete(DeleteBehavior.Restrict);
        b.Entity<Finding>().HasOne<Snapshot>().WithMany().HasForeignKey(x => x.SnapshotId).OnDelete(DeleteBehavior.Restrict);
        b.Entity<Finding>().HasOne<Component>().WithMany().HasForeignKey(x => x.ComponentId).OnDelete(DeleteBehavior.Restrict);
        b.Entity<Review>().HasOne<Finding>().WithMany().HasForeignKey(x => x.FindingId).OnDelete(DeleteBehavior.Restrict);
        b.Entity<RoleBinding>().HasOne<SourceProject>().WithMany().HasForeignKey(x => x.ProjectId).OnDelete(DeleteBehavior.Restrict);
        b.Entity<MachineCredential>().HasOne<SourceProject>().WithMany().HasForeignKey(x => x.ProjectId).OnDelete(DeleteBehavior.Restrict);
    }

    public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        if (ChangeTracker.Entries<AuditEvent>().Any(e => e.State is EntityState.Deleted or EntityState.Modified))
            throw new InvalidOperationException("Audit events are append-only.");
        if (ChangeTracker.Entries<Review>().Any(e => e.State == EntityState.Deleted))
            throw new InvalidOperationException("Review history cannot be deleted.");
        var evidence = new[] { nameof(Snapshot.BomJson), nameof(Snapshot.BomHash), nameof(Snapshot.SubmissionKey), nameof(Snapshot.Commit),
            nameof(Snapshot.Branch), nameof(Snapshot.ApplicationId), nameof(Snapshot.BuildId), nameof(Snapshot.ReleaseId), nameof(Snapshot.CreatedAt) };
        if (ChangeTracker.Entries<Snapshot>().Any(e => e.State == EntityState.Modified && e.Properties.Any(p => p.IsModified && evidence.Contains(p.Metadata.Name))))
            throw new InvalidOperationException("Snapshot evidence is immutable. Submit a new snapshot.");
        return base.SaveChangesAsync(cancellationToken);
    }
}
