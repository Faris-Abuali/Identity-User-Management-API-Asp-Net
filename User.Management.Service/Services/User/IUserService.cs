using Microsoft.AspNetCore.Identity;
using User.Management.Service.Models;

namespace User.Management.Service.Services.User;

public interface IUserService
{
    /// <summary>
    /// Register a new user
    /// </summary>
    /// <param name="user">User model</param>
    /// <returns>The JWT Token if the user has been registered successfully</returns>
    Task<ApiResponse<CreateUserResult>> CreateUserWithTokenAsync(CreateUserDto user);

    Task<ApiResponse<List<string>>> AssignRolesToUserAsync(
        IEnumerable<string> roles,
        IdentityUser user);
    
    Task<ApiResponse<string>> GetOtpByLoginAsync(LoginDto loginDto, IdentityUser user);
}