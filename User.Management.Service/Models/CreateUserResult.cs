using Microsoft.AspNetCore.Identity;

namespace User.Management.Service.Models;

public record CreateUserResult(
    string Token,
    IdentityUser User);