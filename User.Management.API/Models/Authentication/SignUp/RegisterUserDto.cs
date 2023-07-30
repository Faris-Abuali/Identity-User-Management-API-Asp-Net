using System.ComponentModel.DataAnnotations;

namespace User.Management.API.Models.Authentication.SignUp;

public class RegisterUserDto
{
    [Required(ErrorMessage = "Username is required")]
    public required string Username { get; set; }

    [EmailAddress]
    [Required(ErrorMessage = "Email is required")]
    public required string Email { get; set; }

    [Required(ErrorMessage = "Password is required")]
    public required string Password { get; set; }
}
