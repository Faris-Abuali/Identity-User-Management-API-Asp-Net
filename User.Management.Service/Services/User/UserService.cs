using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using User.Management.Service.Models;
using User.Management.Service.Results;

namespace User.Management.Service.Services.User;

public class UserService : IUserService
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly RoleManager<IdentityRole> _roleManager;

    public UserService(
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        RoleManager<IdentityRole> roleManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _roleManager = roleManager;
    }

    public async Task<ApiResponse<CreateUserResult>> CreateUserWithTokenAsync(Models.User userModel)
    {
        // Check if user exists
        var userExists = await _userManager.FindByEmailAsync(userModel.Email);

        if (userExists != null)
        {
            return new ApiResponse<CreateUserResult>
            {
                IsSuccess = false,
                StatusCode = StatusCodes.Status403Forbidden,
                Message = "User already exists!",
            };
        }

        // Add the user to the database
        IdentityUser user = new()
        {
            Email = userModel.Email,
            SecurityStamp = Guid.NewGuid().ToString(),
            UserName = userModel.Username,
            TwoFactorEnabled = true
        };
        
        // Create user
        var result = await _userManager.CreateAsync(user, userModel.Password);
        
        if (!result.Succeeded)
        {
            return new ApiResponse<CreateUserResult>
            {
                IsSuccess = false,
                StatusCode = StatusCodes.Status500InternalServerError,
                Message = "User failed to create!",
            };
        }
        
        // Generate a token to be sent within the email so that user can click the link and confirm their registration
        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        
        return new ApiResponse<CreateUserResult>
        {
            IsSuccess = true,
            StatusCode = StatusCodes.Status201Created,
            Message = "User created successfully",
            Response = new CreateUserResult(Token: token, User: user)
        };
    }

    public async Task<ApiResponse<List<string>>> AssignRolesToUserAsync(
        IEnumerable<string> roles,
        IdentityUser user)
    {
        var assignedRoles = new List<string>();
        
        foreach (var role in roles)
        {
            if (await _roleManager.RoleExistsAsync(role))
            {
                assignedRoles.Add(role);
            }
        }
        
        foreach (var role in assignedRoles)
        {
            // Check if the user is already assigned to the role
            if (!await _userManager.IsInRoleAsync(user, role))
            {
                await _userManager.AddToRoleAsync(user, role);
            }
        }

        return new ApiResponse<List<string>>
        {
            IsSuccess = true,
            StatusCode = StatusCodes.Status200OK,
            Message = "Roles assigned successfully",
            Response = assignedRoles
        };
    }
}