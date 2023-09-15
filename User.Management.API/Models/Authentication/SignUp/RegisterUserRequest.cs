using System.ComponentModel.DataAnnotations;

namespace User.Management.Service.Models.Authentication.SignUp;

public record RegisterUserRequest(
    string Username,
    [EmailAddress]
    [Required(ErrorMessage = "Email is required")]
    string Email,
    [Required(ErrorMessage = "Password is required")]
    string Password,
    [Required(ErrorMessage = "Role is required")]
    string Role);
    
    
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