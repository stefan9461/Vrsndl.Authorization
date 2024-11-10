namespace Vrsndl.Authorization.Client;

internal static class TokenValidationParametersExtensions
{
    public static TokenValidationParameters AddValidateAudience(this TokenValidationParameters validationParameters, JwtValidationOptions options)
    {
        if (!string.IsNullOrEmpty(options.Audience))
        {
            validationParameters.ValidateAudience = true;
            validationParameters.ValidAudience = options.Audience;
            //validationParameters.ValidAudiences = options.Audiences;
        }
        else
        {
            validationParameters.ValidateAudience = false;
        }

        return validationParameters;
    }

    public static TokenValidationParameters AddValidateIssuers(this TokenValidationParameters validationParameters, JwtValidationOptions options)
    {
        if (!string.IsNullOrEmpty(options.Issuer))
        {
            validationParameters.ValidateIssuer = true;
            validationParameters.ValidIssuer = options.Issuer;
            //validationParameters.ValidIssuers = options.Issuers;
        }
        else
        {
            validationParameters.ValidateIssuer = false;
        }

        return validationParameters;
    }

    public static TokenValidationParameters AddSecurityKeyResolver(this TokenValidationParameters validationParameters, IssuerSigningKeyResolver? issuerSigningKeyResolver)
    {
        if (issuerSigningKeyResolver == null)
            throw new ArgumentNullException(nameof(issuerSigningKeyResolver));

        validationParameters.ValidateIssuerSigningKey = true;
        validationParameters.IssuerSigningKeyResolver = issuerSigningKeyResolver;

        return validationParameters;
    }

    public static TokenValidationParameters AddSecurityKey(this TokenValidationParameters validationParameters, JwtValidationOptions options)
    {
        validationParameters.ValidateIssuerSigningKey = true;
        if (options.InternalResolver != null)
            validationParameters.IssuerSigningKeyResolver = options.InternalResolver;
        else if (options.Authorization != null)
        {
            var securityKey = options.Authorization.GetSecurityKey();
            if (securityKey != null)
                validationParameters.IssuerSigningKey = securityKey;
        }
        else
        {
            throw new VrsndlAuthorizationClientConfigurationException("There is no valid authorization available.");
        }

        return validationParameters;
    }
}
