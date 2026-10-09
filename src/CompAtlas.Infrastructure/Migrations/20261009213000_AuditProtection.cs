using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace CompAtlas.Infrastructure.Migrations;

[DbContext(typeof(AtlasDb))]
[Migration("20261009213000_AuditProtection")]
public sealed class AuditProtection : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("""
        CREATE TRIGGER [dbo].[TR_Audit_AppendOnly] ON [dbo].[Audit]
        INSTEAD OF UPDATE, DELETE AS
        BEGIN
            THROW 50001, 'CompAtlas audit events are append-only.', 1;
        END
        """);
    protected override void Down(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("DROP TRIGGER [dbo].[TR_Audit_AppendOnly]");
}
