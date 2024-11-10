namespace Vrsndl.Authorization.Client;

public class VrsndlAuthorizationOptions
{
    public bool? Ignore { get; set; }
    public string? Description { get; set; }
    /// <summary>
    /// Supported scheme's: Bearer
    /// </summary>
    public string? Scheme { get; set; }
    /// <summary>
    /// HMACSHA1, HMACSHA265, HMACSHA384 or HMACSHA512
    /// RSASHA265, RSASHA384 or RSASHA512
    /// </summary>
    public string? Algorithm { get; set; }
    /// <summary>
    /// Clear tekst secret for HMACSHA
    /// </summary>
    public string? Secret { get; set; }
    /// <summary>
    /// Base64 encoded RSA public key
    /// </summary>
    public string? PublicKey { get; set; }
    /// <summary>
    /// RSA public key stored in PEM file
    /// </summary>
    public string? PemFile { get; set; }
    /// <summary>
    /// Issuer as part of the JWT token.
    /// </summary>
    public string? Issuer { get; set; }
    public string? Audience { get; set; }
    private Uri? KeyProvider { get; set; }

    public override string ToString()
    {
        return JsonSerializer.Serialize(this);
    }
}
