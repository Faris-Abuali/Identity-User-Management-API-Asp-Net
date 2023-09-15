using User.Management.Contracts.User;

namespace User.Management.Service.Models;

public class User
{
    private User(string username, string email, string password, List<string>? roles)
    {
        Username = username;
        Email = email;
        Password = password;
        Roles = roles;
    }
    
    public static User Create(string username, string email, string password, List<string>? roles)
    {
        // TODO: Add validation here
        
        // Only if validation passes, create the user
        return new (username, email, password, roles);
    }
    
    public static User From(RegisterUserRequest request)
    {
        return new (request.Username, request.Email, request.Password, request.Roles);
    }

    public string Username { get; }
    
    public string Email { get; }
    
    public string Password { get; }
    
    public List<string>? Roles { get; }
}
   