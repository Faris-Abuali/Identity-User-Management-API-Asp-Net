using Microsoft.AspNetCore.Identity;
using User.Management.Service.Models;
using User.Management.Service.Results;

namespace User.Management.Service.Services.User;

public interface IUserService
{
    /// <summary>
    /// Register a new user
    /// </summary>
    /// <param name="user">User model</param>
    /// <returns>The JWT Token if the user has been registered successfully</returns>
    Task<ApiResponse<CreateUserResult>> CreateUserWithTokenAsync(Models.User user);

    Task<ApiResponse<List<string>>> AssignRolesToUserAsync(
        IEnumerable<string> roles,
        IdentityUser user);
}