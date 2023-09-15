using Microsoft.AspNetCore.Identity;

namespace User.Management.Service.Results;

public record CreateUserResult(
    string Token,
    IdentityUser User);