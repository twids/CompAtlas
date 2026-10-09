using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace CompAtlas.Infrastructure;

public sealed class AtlasDbFactory : IDesignTimeDbContextFactory<AtlasDb>
{
    public AtlasDb CreateDbContext(string[] args) => new(new DbContextOptionsBuilder<AtlasDb>().UseSqlServer(
        Environment.GetEnvironmentVariable("ConnectionStrings__CompAtlas") ??
        "Server=localhost;Database=CompAtlas;Integrated Security=true;Encrypt=true;TrustServerCertificate=false").Options);
}
