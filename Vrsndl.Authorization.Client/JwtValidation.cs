namespace Vrsndl.Authorization.Client;

internal class JwtValidation : IJwtValidation
{
    private static ILogger? _logger;
    private static ILogger Logger
    {
        get
        {
            return _logger ??= VrsndlLoggerFactory.CreateLogger(nameof(VrsndlAuthenticationExtensions));
        }
    }

    private JwtValidationOptions _options;
    private Action<JwtValidationOptions> _optionsCallback;

    public JwtValidation(JwtValidationOptions options, Action<JwtValidationOptions> optionsCallback)
    {
        _options = options;
        _options.InternalResolver = IssuerSigningKeyResolver;
        _optionsCallback = optionsCallback;
    }

    public bool LoadConfiguration(IConfiguration configuration)
    {
        _options.LoadConfiguration(configuration);
        _optionsCallback?.Invoke(_options);

        if (!HasBearerScheme())
        {
            Logger.LogCritical("No validate scheme found. Supported scheme's are: bearer");
            return false;
        }

        return true;
    }

    public TokenValidationParameters GetValidationParameters()
    {
        var validationParameters = new TokenValidationParameters();
        validationParameters.RequireExpirationTime = true;
        validationParameters.ValidateLifetime = true;
        validationParameters.AlgorithmValidator = JwtAlgorithm.DefaultAlgorithmValidator;

        validationParameters
            .AddSecurityKeyResolver(IssuerSigningKeyResolver)
            .AddValidateIssuers(_options)
            .AddValidateAudience(_options);

        return validationParameters;
    }

    internal IEnumerable<SecurityKey> IssuerSigningKeyResolver(
            string token,
            SecurityToken securityToken,
            string kid,
            TokenValidationParameters validationParameters)
    {
        var securityKeys = new List<SecurityKey>();

        // When a external resolver has been given first try to resolve the 
        // security key there.
        if (!string.IsNullOrEmpty(kid) && _options.Resolver != null)
        {
            IssuerSigningKeyResolver r = _options.Resolver;
            var k = r(token, securityToken, kid, validationParameters);
            securityKeys.AddRange(k);
        }

        // Add the security keys as defined in the authorizations section of the configuration
        securityKeys.AddRange(_options.Authorizations.GetSecurityKeys());

        // Also added the locally defined security key.
        var securityKey = _options.Authorization.GetSecurityKey();
        if (securityKey != null)
            securityKeys.Add(securityKey);

        return securityKeys;
    }

    public bool HasBearerScheme()
    {
        var bearerScheme = string.Equals(_options.Scheme, JwtBearerDefaults.AuthenticationScheme, StringComparison.OrdinalIgnoreCase);
        return bearerScheme;
    }

    public bool ValidateAuthorizationOptions()
    {
        bool isValid = _options?.Authorization?.ValidateAuthorizationOptions(_options.Scheme, _options.Issuer, _options.Audience) ?? true;

        if (_options?.Authorizations == null)
            return isValid;

        foreach (var authorizationOptions in _options.Authorizations)
        {
            isValid &= authorizationOptions.ValidateAuthorizationOptions(_options.Scheme, _options.Issuer, _options.Audience);
        }

        return isValid;
    }
}
