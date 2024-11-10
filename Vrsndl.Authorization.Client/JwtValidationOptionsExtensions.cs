namespace Vrsndl.Authorization.Client;

internal static class JwtValidationOptionsExtensions
{
    private static ILogger? _logger = null;

    private static ILogger Logger
    {
        get
        {
            _logger ??= VrsndlLoggerFactory.CreateLogger(nameof(JwtValidationOptionsExtensions));
            return _logger;
        }
    }

    //public JwtValidation(IConfiguration configuration)
    //{
    //    Logger = VrsndlHomeWizardLoggerFactory.CreateLogger(nameof(JwtValidation));

    //    var protectedSection = configuration.GetSection(ProtectedSettingsLabel);
    //    var authorizationSection = protectedSection.GetSection(AuthorizationLabel);

    //    Scheme = authorizationSection.GetValue<string>("Scheme");
    //    Logger?.LogInformation($"Using authorization scheme [{Scheme ?? "none"}]");

    //    Algorithm = authorizationSection.GetValue<string>("Algorithm");
    //    Logger?.LogInformation($"Using authorization algorithm [{Algorithm ?? "none"}]");

    //    if (Algorithm.IsSymmetricAlgorithm())
    //    {
    //        Secret = authorizationSection.GetValue<string>("Secret");
    //        var s = string.IsNullOrEmpty(Secret) ? "none" : "****";
    //        Logger?.LogInformation($"Using authorization secret [{s}]");
    //    }
    //    else if (Algorithm.IsASymmetricAlgorithm())
    //    {
    //        PemFile = authorizationSection.GetValue<string>("PemFile");
    //        Logger?.LogInformation($"Using authorization pemFile [{PemFile ?? "none"}]");

    //        PublicKey = authorizationSection.GetValue<string>("PublicKey");
    //        var s = string.IsNullOrEmpty(PublicKey) ? "none" : "****";
    //        Logger?.LogInformation($"Using authorization public key [{s}]");
    //    }

    //    Issuer = authorizationSection.GetValue<string>("Issuer");
    //    Logger?.LogInformation($"Using authorization issuer [{Issuer}]");

    //    Audience = authorizationSection.GetValue<string>("Audience");
    //    Logger?.LogInformation($"Using authorization audience [{Audience}]");

    //    var keyProvider = authorizationSection.GetValue<string>("KeyProvider");
    //    if (!string.IsNullOrEmpty(keyProvider))
    //        KeyProvider = new Uri(keyProvider);

    //    var publicKeyFile = authorizationSection.GetValue<string>("KeyProvider");
    //}

    public static SecurityKey? GetSecurityKeyFromPemFile(this string pFile)
    {
        string? pemFile = pFile;
        bool notFullyQualified = Path.IsPathFullyQualified(pemFile);
        if (!notFullyQualified)
            pemFile = FileExtensions.FindFullFilePath(pemFile);

        if (string.IsNullOrEmpty(pemFile))
        {
            string msgPemFileNotFound = "Given PEM file [{0}] was not found, cannot secure API";
            throw new VrsndlAuthorizationClientConfigurationException(string.Format(msgPemFileNotFound, pemFile));
        }

        string publicPem = File.ReadAllText(pemFile);
        RSA? publicRSA = publicPem.ImportPublicKeyFromPem();

        if (publicRSA == null)
        {
            string msgPemFileRsaPublicKeyMissing = "Given PEM file [{0}] does not contain a valid 'RSA PUBLIC KEY'";
            throw new VrsndlAuthorizationClientConfigurationException(string.Format(msgPemFileRsaPublicKeyMissing, pemFile));
        }

        return new RsaSecurityKey(publicRSA);
    }

    public static SecurityKey? GetSecurityKeyFromPublicKey(this string publicKey)
    {
        var bytes = Convert.FromBase64String(publicKey);
        RSA rsa = RSA.Create();
        rsa.ImportRSAPublicKey(bytes, out _);
        return new RsaSecurityKey(rsa);

        //if (string.IsNullOrEmpty(publicKey))
        //{
        //    string message = $"Given PEM file [{PemFile}] was not found, cannot secure API";
        //    Logger?.LogCritical(message);
        //    throw new AuthorizationClientConfigurationException(message);
        //}
    }

    private static object Lock = new object();
    public static void LoadConfiguration(this JwtValidationOptions options, IConfiguration configuration)
    {
        lock (Lock)
        {
            configuration
                .GetSection(JwtValidationOptions.AuthorizationLabel)
                .Bind(options);
        }
    }
}
