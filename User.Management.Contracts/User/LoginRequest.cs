
namespace User.Management.Contracts.User;

public record LoginRequest(
    string Username,
    string Password);