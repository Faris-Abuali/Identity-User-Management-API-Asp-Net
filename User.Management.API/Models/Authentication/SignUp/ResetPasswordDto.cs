using System.ComponentModel.DataAnnotations;

namespace User.Management.Service.Models.Authentication.SignUp;

public class ResetPasswordDto
{
    [Required]
    public string? Password { get; set; }

    [Compare(nameof(Password), ErrorMessage = "Confirm Password field doesn't match Password field")]
    public string? ConfirmPassword { get; set; }

    public required string Email { get; set; }

    public required string Token { get; set; }
}
