using CompAtlas.Core;
using CompAtlas.Infrastructure;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace CompAtlas.Tests;

public sealed class SqlServerFactAttribute : FactAttribute
{
    public SqlServerFactAttribute() { if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("COMPATLAS_TEST_SQLSERVER"))) Skip = "Set COMPATLAS_TEST_SQLSERVER to run real SQL Server migration and concurrency tests."; }
}
public sealed class SqlServerTests
{
    [SqlServerFact]
    public async Task Backup_restore_preserves_pending_synchronization_jobs()
    {
        var folder = Path.Combine(Path.GetTempPath(), "CompAtlas_Test_" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(folder);
        var sourceName = "CompAtlas_Test_" + Guid.NewGuid().ToString("N"); var restoredName = "CompAtlas_Test_" + Guid.NewGuid().ToString("N");
        var original = new SqlConnectionStringBuilder(Environment.GetEnvironmentVariable("COMPATLAS_TEST_SQLSERVER")) { InitialCatalog = sourceName };
        var restored = new SqlConnectionStringBuilder(original.ConnectionString) { InitialCatalog = restoredName };
        await using var db = new AtlasDb(new DbContextOptionsBuilder<AtlasDb>().UseSqlServer(original.ConnectionString).Options);
        await using var recovery = new AtlasDb(new DbContextOptionsBuilder<AtlasDb>().UseSqlServer(restored.ConnectionString).Options);
        try
        {
            await db.Database.MigrateAsync(); var queue = new JobQueue(db, TimeProvider.System);
            var job = await queue.Enqueue(JobKind.ReviewSync, Guid.NewGuid(), "pending-review");
            await using var sql = new SqlConnection(original.ConnectionString); await sql.OpenAsync();
            var files = new List<(string Name, int Type)>();
            await using (var command = new SqlCommand("SELECT name,type FROM sys.database_files", sql))
            await using (var reader = await command.ExecuteReaderAsync()) while (await reader.ReadAsync()) files.Add((reader.GetString(0), reader.GetByte(1)));
            var backup = Path.Combine(folder, "backup.bak");
            await using (var command = new SqlCommand("BACKUP DATABASE [" + sourceName + "] TO DISK=@path WITH INIT", sql))
            { command.Parameters.AddWithValue("@path", backup); await command.ExecuteNonQueryAsync(); }
            await using (var command = new SqlCommand("RESTORE DATABASE [" + restoredName + "] FROM DISK=@path WITH MOVE @dataName TO @dataPath, MOVE @logName TO @logPath", sql))
            {
                command.Parameters.AddWithValue("@path", backup); command.Parameters.AddWithValue("@dataName", files.Single(f => f.Type == 0).Name);
                command.Parameters.AddWithValue("@logName", files.Single(f => f.Type == 1).Name); command.Parameters.AddWithValue("@dataPath", Path.Combine(folder, "recovered.mdf"));
                command.Parameters.AddWithValue("@logPath", Path.Combine(folder, "recovered.ldf")); await command.ExecuteNonQueryAsync();
            }
            var recovered = await recovery.Jobs.SingleAsync(j => j.Id == job.Id); Assert.Equal(JobState.Queued, recovered.State);
            Assert.NotNull(await new JobQueue(recovery, TimeProvider.System).Claim(false, null, null, default));
        }
        finally
        {
            await recovery.Database.EnsureDeletedAsync(); await db.Database.EnsureDeletedAsync();
            SqlConnection.ClearAllPools(); Directory.Delete(folder, true);
        }
    }
    [SqlServerFact]
    public async Task Migrations_job_claims_and_audit_trigger_work_on_sql_server()
    {
        var connection = new SqlConnectionStringBuilder(Environment.GetEnvironmentVariable("COMPATLAS_TEST_SQLSERVER")) { InitialCatalog = "CompAtlas_Test_" + Guid.NewGuid().ToString("N") };
        var options = new DbContextOptionsBuilder<AtlasDb>().UseSqlServer(connection.ConnectionString).Options;
        await using var db = new AtlasDb(options);
        try
        {
            await db.Database.MigrateAsync();
            db.Audit.Add(new AuditEvent { ActorSid = "test", Action = "Created" }); await db.SaveChangesAsync();
            await Assert.ThrowsAsync<SqlException>(() => db.Database.ExecuteSqlRawAsync("UPDATE [Audit] SET [Action]='tampered'"));
            var queue = new JobQueue(db, TimeProvider.System);
            await queue.Enqueue(JobKind.Discover, Guid.NewGuid(), "sql-claim");
            await using var secondDb = new AtlasDb(options);
            var claimed = await Task.WhenAll(queue.Claim(false, null, null, default), new JobQueue(secondDb, TimeProvider.System).Claim(false, null, null, default));
            Assert.Single(claimed, j => j != null);
            var project = Guid.NewGuid();
            for (var i = 0; i < 3; i++) await queue.Enqueue(JobKind.Collect, Guid.NewGuid(), "collector-" + i, project);
            await using var collectorOne = new AtlasDb(options); await using var collectorTwo = new AtlasDb(options); await using var collectorThree = new AtlasDb(options);
            var collectors = await Task.WhenAll(new JobQueue(collectorOne, TimeProvider.System).Claim(true, project, Guid.NewGuid(), default),
                new JobQueue(collectorTwo, TimeProvider.System).Claim(true, project, Guid.NewGuid(), default),
                new JobQueue(collectorThree, TimeProvider.System).Claim(true, project, Guid.NewGuid(), default));
            Assert.Equal(2, collectors.Count(j => j != null));
        }
        finally { await db.Database.EnsureDeletedAsync(); }
    }
}
