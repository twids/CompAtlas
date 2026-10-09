using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace CompAtlas.Infrastructure;

public static class Registration
{
    public static IServiceCollection AddCompAtlas(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<AtlasOptions>(configuration.GetSection("CompAtlas"));
        services.AddSingleton(TimeProvider.System);
        services.AddDbContext<AtlasDb>(o => o.UseSqlServer(configuration.GetConnectionString("CompAtlas") ??
            "Server=localhost;Database=CompAtlas;Integrated Security=true;Encrypt=true;TrustServerCertificate=false"));
        services.AddScoped<ProjectAccess>(); services.AddScoped<JobQueue>(); services.AddScoped<SubmissionService>();
        services.AddScoped<Reports>(); services.AddScoped<ReviewService>(); services.AddScoped<Discovery>();
        services.AddScoped<Analysis>(); services.AddScoped<Malware>(); services.AddScoped<AzureClient>();
        services.AddScoped<DependencyTrackClient>();
        services.AddScoped<ManualDeclarations>();
        return services;
    }
}
