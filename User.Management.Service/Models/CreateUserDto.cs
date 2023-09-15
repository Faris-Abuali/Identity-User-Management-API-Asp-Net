namespace User.Management.Service.Models;

public record CreateUserDto(
    string Username,
    string Email,
    string Password,
    List<string>? Roles,
    bool TwoFactorEnabled = false);