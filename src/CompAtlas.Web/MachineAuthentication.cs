using System.Security.Claims;
using System.Text.Encodings.Web;
using CompAtlas.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace CompAtlas.Web;

public sealed class MachineAuthentication(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger,
    UrlEncoder encoder, AtlasDb db, TimeProvider clock) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var authorization = Request.Headers.Authorization.ToString();
        if (!authorization.StartsWith("Bearer ", StringComparison.Ordinal)) return AuthenticateResult.NoResult();
        var secret = authorization[7..];
        if (secret.Length != 64 || secret.Any(c => !Uri.IsHexDigit(c))) return AuthenticateResult.Fail("Invalid credential.");
        var hash = Secrets.Hash(secret);
        var credential = await db.MachineCredentials.AsNoTracking().SingleOrDefaultAsync(k => k.SecretHash == hash && !k.Revoked && k.ExpiresAt > clock.GetUtcNow(), Context.RequestAborted);
        if (credential == null) return AuthenticateResult.Fail("Invalid credential.");
        var claims = new List<Claim> { new("atlas:machine", "true"), new("atlas:project", credential.ProjectId.ToString()),
            new("atlas:credential", credential.Id.ToString()), new(ClaimTypes.NameIdentifier, credential.Id.ToString()) };
        if (credential.CanCollect) claims.Add(new Claim("atlas:collect", "true"));
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme.Name)), Scheme.Name));
    }
}
