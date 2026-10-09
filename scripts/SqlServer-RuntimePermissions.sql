-- Apply in the CompAtlas database using a DBA identity after migrations.
-- Add the IIS and Worker service users to this role using your approved provisioning process.
IF DATABASE_PRINCIPAL_ID(N'CompAtlasRuntime') IS NULL
    CREATE ROLE [CompAtlasRuntime];
GRANT SELECT, INSERT, UPDATE, DELETE ON SCHEMA::[dbo] TO [CompAtlasRuntime];
DENY UPDATE, DELETE ON OBJECT::[dbo].[Audit] TO [CompAtlasRuntime];
DENY DELETE ON OBJECT::[dbo].[Reviews] TO [CompAtlasRuntime];
DENY ALTER ON SCHEMA::[dbo] TO [CompAtlasRuntime];
-- The migration identity is separate. Runtime identities must not be db_owner or sysadmin.
