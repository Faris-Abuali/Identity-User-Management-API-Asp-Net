using Mapster;
using User.Management.Contracts.User;
using User.Management.Service.Models;

namespace User.Management.API.Common.Mapping;

public class AuthenticationMappingConfig : IRegister
{
    public void Register(TypeAdapterConfig config)
    {
        config.NewConfig<LoginRequest, LoginDto>()
            .Map(dest => dest.Username, src => src.Username)
            .Map(dest => dest.Password, src => src.Password);

        config.NewConfig<RegisterUserRequest, CreateUserDto>();
    }
}