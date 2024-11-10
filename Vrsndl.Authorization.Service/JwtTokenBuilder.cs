using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Centric.Authorization.Client;

public class JwtTokenBuilder
{
    private SecurityTokenDescriptor _descriptor;
    private int _lifetimeInMinutes = 60;

    public JwtTokenBuilder()
    {
        _descriptor = new SecurityTokenDescriptor();
        _descriptor.Subject = new ClaimsIdentity();
    }

    public string build()
    {
        JsonWebTokenHandler _handler = new JsonWebTokenHandler();

        _descriptor.IssuedAt = DateTime.UtcNow;
        _descriptor.NotBefore = DateTime.UtcNow;
        _descriptor.Expires = DateTime.UtcNow.AddMinutes(_lifetimeInMinutes);

        var token = _handler.CreateToken(_descriptor);

        return token;
    }

    public JwtTokenBuilder AddClaim(string key, string? value)
    {
        if (!string.IsNullOrEmpty(value))
        {
            var claim = new Claim(key, value);
            _descriptor.Subject.AddClaim(claim);
        }

        return this;
    }

    public JwtTokenBuilder SetAudience(string audience)
    {
        _descriptor.Audience = audience;

        return this;
    }

    /// <summary>
    /// Number of minutes until expiration
    /// </summary>
    /// <param name="minutes">the number of minutes that the token will be valid</param>
    /// <returns></returns>
    public JwtTokenBuilder SetLifetime(int minutes)
    {
        this._lifetimeInMinutes = minutes;

        return this;
    }

    public JwtTokenBuilder SetIssuer(string issuer)
    {
        _descriptor.Issuer = issuer;

        return this;
    }

    public JwtTokenBuilder SetSubject(string subject)
    {
        AddClaim("sub", subject);

        return this;
    }

    public JwtTokenBuilder SetSigningCredentials(SigningCredentials signingCredentials)
    {
        _descriptor.SigningCredentials = signingCredentials;

        return this;
    }

    public JwtTokenBuilder SetSecurityKey(SymmetricSecurityKey securityKey, string algorithm)
    {
        switch (algorithm)
        {
            case SecurityAlgorithms.HmacSha256:
            case SecurityAlgorithms.HmacSha384:
            case SecurityAlgorithms.HmacSha512:
                _descriptor.SigningCredentials = new SigningCredentials(securityKey, algorithm);
                return this;
            default:
                throw new NotImplementedException($"Algorithm given does not match the security Key");
        }
    }
}
