namespace User.Management.Contracts.User;
using System.ComponentModel.DataAnnotations;

public record RegisterUserRequest(
    string Username,
    [EmailAddress]
    [Required(ErrorMessage = "Email is required")]
    string Email,
    [Required(ErrorMessage = "Password is required")]
    string Password,
    [Required(ErrorMessage = "Role is required")]
    List<string>? Roles,
    bool TwoFactorEnabled = false);


// public class RegisterUserRequest
// {
//     [Required(ErrorMessage = "Username is required")]
//     public required string Username { get; set; }
//
//     [EmailAddress]
//     [Required(ErrorMessage = "Email is required")]
//     public required string Email { get; set; }
//
//     [Required(ErrorMessage = "Password is required")]
//     public required string Password { get; set; }
// }