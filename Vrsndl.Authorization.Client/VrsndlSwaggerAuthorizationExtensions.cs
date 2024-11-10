using Swashbuckle.AspNetCore.SwaggerGen;

namespace Vrsndl.Authorization.Client;

public static class VrsndlSwaggerAuthorizationExtensions
{
    public static IServiceCollection AddVrsndlSwaggerAuthorization(this IServiceCollection services)
    {
        if (services == null)
            throw new ArgumentNullException(nameof(services));

        // Make sure we can log.
        services.AddVrsndlLoggerFactory();
        var logger = VrsndlLoggerFactory.CreateLogger(nameof(VrsndlSwaggerAuthorizationExtensions));

        logger.LogInformation("Added SwaggerGen");

        // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(options =>
        {
            AddVrsndlSwaggerSecurity(options);
        });
        return services;
    }

    private static void AddVrsndlSwaggerSecurity(SwaggerGenOptions options)
    {
        var reference = new OpenApiReference
        {
            Type = ReferenceType.SecurityScheme,
            Id = JwtBearerDefaults.AuthenticationScheme
        };

        var securityScheme = new OpenApiSecurityScheme
        {
            Name = "Authorization",
            Type = SecuritySchemeType.ApiKey,
            Scheme = JwtBearerDefaults.AuthenticationScheme,
            BearerFormat = "JWT",
            In = ParameterLocation.Header,
            Description = "JWT authorization header using the bearer scheme",
            Reference = reference,
        };

        options.AddSecurityDefinition(JwtBearerDefaults.AuthenticationScheme, securityScheme);

        options.AddSecurityRequirement(new OpenApiSecurityRequirement
        {
            {
                securityScheme,
                Array.Empty<string>()
            }
        });
    }
}
