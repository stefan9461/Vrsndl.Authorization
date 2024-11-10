namespace Vrsndl.Authorization.Client;


public static class VrsndlAuthenticationExtensions
{
    private static ILoggerFactory? _loggerFactory;
    private static ILoggerFactory LoggerFactory
    {
        get
        {
            return _loggerFactory ?? new LoggerFactory();
        }
    }

    private static ILogger? _logger;
    private static ILogger Logger
    {
        get
        {
            return _logger ??= LoggerFactory.CreateLogger(nameof(VrsndlAuthenticationExtensions));
        }
    }

    public static IServiceCollection AddVrsndlAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        return AddVrsndlAuthentication(services, configuration, (_) => { });
    }

    public static IServiceCollection AddVrsndlAuthentication(this IServiceCollection services, IConfiguration configuration, Action<JwtValidationOptions> optionsCallback)
    {
        // Make sure we can log.
        services.AddVrsndlLoggerFactory();

        Logger.LogInformation("Start adding Vrsndl Authentication");

        // Create options as singleton
        var options = new JwtValidationOptions();
        services.AddSingleton<JwtValidationOptions>(options);

        // Create validator as singleton
        var jwtValidation = new JwtValidation(options, optionsCallback);
        services.AddSingleton<JwtValidation>(jwtValidation);

        try
        {
            // Load the configuration or throws exception!
            jwtValidation.LoadConfiguration(configuration);

            services.AddVrsndlAuthenticationBearer(jwtValidation);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error while loading the configuration");
            throw;
        }

        return services;
    }

    private static IServiceCollection AddVrsndlAuthenticationBearer(this IServiceCollection services, JwtValidation validator)
    {
        if (!validator.ValidateAuthorizationOptions())
            throw new VrsndlAuthorizationClientConfigurationException("Not valid authorization scheme defined");
        //Logger.LogCritical("The authorization(s) contain error(s). Please check configuration.");

        var vaidationParameters = validator.GetValidationParameters();

        services
            .AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                //options.RequireHttpsMetadata = false;
                options.SaveToken = false;
                options.TokenValidationParameters = vaidationParameters;
                options.MapInboundClaims = false;

                options.Events = new JwtBearerEvents()
                {
                    OnMessageReceived = context =>
                    {
                        var accessToken = context.Request.Query["access_token"];

                        var path = context.HttpContext.Request.Path;

                        if (string.IsNullOrEmpty(context.Token) && !string.IsNullOrEmpty(accessToken))
                            context.Token = accessToken;

                        return Task.CompletedTask;
                    }
                };
            });

        Logger.LogInformation("Done adding Vrsndl Authentication");
        return services;
    }
}
