using System.Reflection;
using Mapster;
using MapsterMapper;

namespace User.Management.API.Common.Mapping;

public static class DependencyInjection
{
    public static IServiceCollection AddMappings(this IServiceCollection services)
    {
        var config = TypeAdapterConfig.GlobalSettings;
        config.Scan(Assembly.GetExecutingAssembly());
        
        services.AddSingleton(config);
        services.AddScoped<IMapper, ServiceMapper>(); // ServiceMapper is a wrapper around TypeAdapterConfig that implements IMapper
        
        return services;
    }
}