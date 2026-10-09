using System.Security.Claims;
using CompAtlas.Core;
using CompAtlas.Infrastructure;
using CompAtlas.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using System.Threading.RateLimiting;

var runtimeArgs = new List<string>();
for (var i = 0; i < args.Length; i++)
{
    if (args[i] == "--migrate") continue;
    if (args[i] == "--bootstrap-sid") { i++; continue; }
    runtimeArgs.Add(args[i]);
}
var builder = WebApplication.CreateBuilder(runtimeArgs.ToArray());
builder.Services.AddCompAtlas(builder.Configuration);
builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 12 * 1024 * 1024);
builder.Services.AddAuthentication("Atlas")
    .AddPolicyScheme("Atlas", "Windows or project machine identity", o => o.ForwardDefaultSelector = ctx =>
        ctx.Request.Headers.Authorization.ToString().StartsWith("Bearer ", StringComparison.Ordinal) ? "Machine" : NegotiateDefaults.AuthenticationScheme)
    .AddNegotiate().AddScheme<AuthenticationSchemeOptions, MachineAuthentication>("Machine", _ => { });
builder.Services.AddAuthorization(o =>
{
    o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
    o.AddPolicy("Interactive", p => p.RequireAuthenticatedUser().RequireAssertion(c => !c.User.HasClaim("atlas:machine", "true")));
    o.AddPolicy("Machine", p => p.AddAuthenticationSchemes("Machine").RequireClaim("atlas:machine", "true"));
});
builder.Services.AddAntiforgery(o => { o.Cookie.SecurePolicy = CookieSecurePolicy.Always; o.Cookie.HttpOnly = true; o.Cookie.SameSite = SameSiteMode.Strict; });
builder.Services.AddRazorPages(o => o.Conventions.AuthorizeFolder("/", "Interactive"));
builder.Services.AddProblemDetails();
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.AddPolicy("machine", context => RateLimitPartition.GetFixedWindowLimiter(
        context.User.FindFirstValue("atlas:credential") ?? context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 120, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
});
var app = builder.Build();
if (args.Contains("--migrate") || args.Contains("--bootstrap-sid"))
{
    await using var scope = app.Services.CreateAsyncScope();
    var db = scope.ServiceProvider.GetRequiredService<AtlasDb>();
    if (args.Contains("--migrate")) await db.Database.MigrateAsync();
    var index = Array.IndexOf(args, "--bootstrap-sid");
    if (index >= 0)
    {
        if (index + 1 >= args.Length) throw new ArgumentException("Supply an administrator AD group SID.");
        var binding = new RoleBinding { GroupSid = args[index + 1], Role = AccessRole.Administrator };
        ProjectAccess.ValidateBinding(binding);
        if (await db.RoleBindings.AnyAsync()) throw new InvalidOperationException("Bootstrap is allowed only before any roles exist.");
        db.RoleBindings.Add(binding);
        db.Audit.Add(new AuditEvent { ActorSid = "local-bootstrap", Action = "AdministratorBootstrapped", Target = binding.GroupSid });
        await db.SaveChangesAsync();
    }
    return;
}
app.UseExceptionHandler(new ExceptionHandlerOptions
{
    StatusCodeSelector = error => error is Microsoft.AspNetCore.Antiforgery.AntiforgeryValidationException
        ? StatusCodes.Status400BadRequest : StatusCodes.Status500InternalServerError
});
app.UseHsts();
app.UseHttpsRedirection();
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers.ContentSecurityPolicy = "default-src 'self'; script-src 'none'; style-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
    ctx.Response.Headers.XContentTypeOptions = "nosniff";
    ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
    ctx.Response.Headers.CacheControl = "no-store";
    await next();
});
app.UseStaticFiles();
app.UseAuthentication();
app.UseRateLimiter();
app.UseAuthorization();
app.UseAntiforgery();
app.MapRazorPages();
app.MapAtlasApi();
app.Run();

public partial class Program { }
