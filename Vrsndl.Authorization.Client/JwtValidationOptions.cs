namespace Vrsndl.Authorization.Client;

public class JwtValidationOptions
{
    public static readonly string AuthorizationLabel = "AuthorizationSettings";
    public string? Issuer { get; set; }
    internal IList<string>? Issuers { get; set; } = new List<string>();
    public string? Audience { get; set; }
    internal IList<string>? Audiences { get; set; } = new List<string>();
    public string? Scheme { get; set; }
    public IssuerSigningKeyResolver? Resolver { get; set; }
    internal IssuerSigningKeyResolver? InternalResolver { get; set; }
    public VrsndlAuthorizationOptions? Authorization { get; set; }
    public List<VrsndlAuthorizationOptions>? Authorizations { get; set; }

    public override string ToString()
    {
        return JsonSerializer.Serialize(this);
    }
}
