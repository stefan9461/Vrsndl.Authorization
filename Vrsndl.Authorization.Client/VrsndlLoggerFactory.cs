namespace Vrsndl.Authorization.Client;

public static class VrsndlLoggerFactory
{
    private static ILoggerFactory? _loggerFactory;
    private static ILoggerFactory LoggerFactory
    {
        get
        {
            return _loggerFactory ?? new LoggerFactory();
        }
    }

    public static IServiceCollection AddVrsndlLoggerFactory(this IServiceCollection services)
    {
        if (services == null)
            throw new ArgumentNullException(nameof(services));

        if (_loggerFactory == null)
        {
            var provider = services.BuildServiceProvider();
            _loggerFactory = provider.GetService<ILoggerFactory>();
        }

        return services;
    }

    public static ILogger CreateLogger(string categoryName) => LoggerFactory.CreateLogger(categoryName);
    public static ILogger CreateLogger(Type type) => LoggerFactory.CreateLogger(type);
}
