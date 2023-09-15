using System.ComponentModel.DataAnnotations;

namespace User.Management.Service.Models.Authentication.Login
{
    public class LoginDto
    {
        [Required(ErrorMessage = "Username is required")]
        public required string Username { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public required string Password { get; set; }
    }
}
