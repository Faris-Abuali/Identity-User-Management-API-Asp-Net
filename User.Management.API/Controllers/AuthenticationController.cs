using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using User.Management.API.Models;
using User.Management.Service.Services.User;
using User.Management.Service.Services.Email;
using User.Management.Service.Models;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.ComponentModel.DataAnnotations;
using MapsterMapper;
using Microsoft.AspNetCore.Authorization;
using User.Management.Service.Models.Authentication.SignUp;
using RegisterUserRequest = User.Management.Contracts.User.RegisterUserRequest;
using UserModel = User.Management.Service.Models.User;

namespace User.Management.API.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthenticationController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IEmailService _emailService;
    private readonly IUserService _userService;
    private readonly IConfiguration _configuration;
    private readonly IMapper _mapper;

    public AuthenticationController(UserManager<IdentityUser> userManager,
        RoleManager<IdentityRole> roleManager,
        SignInManager<IdentityUser> signInManager,
        IUserService userService,
        IEmailService emailService,
        IConfiguration configuration, 
        IMapper mapper)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _signInManager = signInManager;
        _userService = userService;
        _emailService = emailService;
        _configuration = configuration;
        _mapper = mapper;
    }

    [HttpPost]
    [Route("register")]
    public async Task<IActionResult> Register([FromBody] RegisterUserRequest request)
    {
        // var userModel = UserModel.From(request);
        var createUserDto = _mapper.Map<CreateUserDto>(request);

        var createUserResult = await _userService.CreateUserWithTokenAsync(createUserDto);

        if (!createUserResult.IsSuccess)
        {
            return StatusCode(
                statusCode: createUserResult.StatusCode,
                value: new Response { Status = "Success", Message = createUserResult.Message, IsSuccess = true });
        }

        var user = createUserResult.Response!.User;

        if (request.Roles is not null)
        {
            // Assign roles to the user
            await _userService.AssignRolesToUserAsync(request.Roles, user);
        }

        var token = createUserResult.Response!.Token;

        // The link once clicked will lead the user to the action method whose name is `ConfirmEmail`
        var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { token, email = request.Email },
            Request.Scheme);

        // Specify the email recipient(s) and prepare the email subject and content
        var message = new Message(new string[] { user.Email }, "Account Confirmation", confirmationLink!);

        // Now send the email
        _emailService.SendEmail(message);

        return StatusCode(
            StatusCodes.Status201Created,
            new Response
            {
                Status = "Success",
                Message = $"User Created and Email sent to {request.Email} successfully",
                IsSuccess = true
            });
    }

    [HttpGet("confirm-email")]
    public async Task<IActionResult> ConfirmEmail(string token, string email)
    {
        var user = await _userManager.FindByEmailAsync(email);

        if (user == null)
        {
            return StatusCode(StatusCodes.Status400BadRequest,
                new Response { Status = "Error", Message = "No user with this email exists!" });
        }

        var result = await _userManager.ConfirmEmailAsync(user, token);

        if (!result.Succeeded)
        {
            return StatusCode(StatusCodes.Status500InternalServerError,
                new Response { Status = "Error", Message = "Something Went Wrong" });
        }

        return StatusCode(StatusCodes.Status200OK,
            new Response { Status = "Success", Message = "Email confirmed successfully" });
    }

    [HttpPost]
    [Route("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto loginUserDto)
    {
        // Checking user
        var user = await _userManager.FindByNameAsync(loginUserDto.Username);

        if (user is null)
        {
            return StatusCode(StatusCodes.Status401Unauthorized,
                new Response { Status = "Error", Message = "Invalid login credentials" });        
        }

        // ------------- Two Factor Authentication -------------
        if (user.TwoFactorEnabled)
        {
            if (user.Email is null)
            {
                return StatusCode(StatusCodes.Status400BadRequest,
                    new Response { Status = "Error", Message = "Email is required for Two Factor Authentication" });
            }
            
            var loginModel = _mapper.Map<LoginDto>(loginUserDto);
            var getOtpResult = await _userService.GetOtpByLoginAsync(loginModel, user);
            var token = getOtpResult.Response;
            
            // Specify the email recipient(s) and prepare the email subject and content
            var message = new Message(new string[] { user.Email }, "Two Factor OTP Confirmation", token!);

            // Now send the email
            _emailService.SendEmail(message);

            return StatusCode(StatusCodes.Status200OK,
                new Response { Status = "Success", Message = $"an OTP has been sent to your email: {user.Email}" });
        }
        // ------------- End of Two Factor Authentication -------------

        // Checking password
        var isValidPassword = await _userManager.CheckPasswordAsync(user, loginUserDto.Password);

        if (!isValidPassword)
        {
            return StatusCode(StatusCodes.Status401Unauthorized,
                new Response { Status = "Error", Message = "Invalid login credentials" });
        }

        var isEmailConfirmed = user.EmailConfirmed;

        if (!isEmailConfirmed)
        {
            return StatusCode(StatusCodes.Status403Forbidden,
                new Response { Status = "Error", Message = "You must confirm you email then login" });
        }

        var jwtToken = await GenerateAndReturnJwtToken(user);

        return Ok(new
        {
            token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
            expiration = jwtToken.ValidTo
        });
    }

    [HttpPost]
    [Route("login-2FA")]
    public async Task<IActionResult> LoginWithOtp(string code, string username)
    {
        var user = await _userManager.FindByNameAsync(username);

        if (user is null)
        {
            return StatusCode(StatusCodes.Status404NotFound,
                new Response { Status = "Error", Message = "Invalid Two Factor OTP Code" });
        }

        // This validates the two factor sign in code & creates & signs in the user
        var signInResult = await _signInManager.TwoFactorSignInAsync(
            provider: TokenOptions.DefaultEmailProvider,
            code,
            isPersistent: true, // whether the sign-in cookie should persist after the browser is closed.
            rememberClient: true); // whether the current browser should remember, suppressing all further two factor authentication prompts.

        if (!signInResult.Succeeded)
        {
            return StatusCode(StatusCodes.Status400BadRequest,
                new Response { Status = "Error", Message = "Invalid Two Factor OTP Code" });
        }

        var jwtToken = await GenerateAndReturnJwtToken(user);

        return Ok(new
        {
            token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
            expiration = jwtToken.ValidTo
        });
    }

    [HttpPost]
    [Route("forgot-password")]
    [AllowAnonymous] // means that this method doesn't require authorization
    public async Task<IActionResult> ForgotPassword([Required] string email)
    {
        var user = await _userManager.FindByEmailAsync(email);

        if (user is null)
        {
            return StatusCode(StatusCodes.Status400BadRequest,
                new Response
                    { Status = "Error", Message = $"Couldn't send link to the specified email: ${email}" });
        }

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);

        // The link once clicked will lead the user to the action method whose name is `ResetPassword`
        var forgotPasswordLink = Url.Action(nameof(ResetPassword), "Authentication", new { token, email = user.Email },
            Request.Scheme);

        // Specify the email recepient(s) and prepare the email subject and content
        var message = new Message(new string[] { user.Email! }, "Forgot Password Link", forgotPasswordLink!);

        // Now send the email
        _emailService.SendEmail(message);

        return StatusCode(StatusCodes.Status200OK,
            new Response
            {
                Status = "Success", Message = $"Reset Forgotten Password Request has been sent to email: {user.Email}"
            });
        ;
    }


    [HttpGet("reset-password")]
    public IActionResult ResetPassword(string token, string email)
    {
        var model = new ResetPasswordDto { Token = token, Email = email };

        return Ok(model);
    }

    [HttpPost]
    [Route("reset-password")]
    [AllowAnonymous] // means that this method doesn't require authorization
    public async Task<IActionResult> ResetPassword(ResetPasswordDto resetPasswordDto)
    {
        var user = await _userManager.FindByEmailAsync(resetPasswordDto.Email);

        if (user is null)
        {
            return StatusCode(StatusCodes.Status400BadRequest,
                new Response
                {
                    Status = "Error",
                    Message = $"Couldn't find a user with the specified email: ${resetPasswordDto.Email}"
                });
        }

        var resetPasswordResult =
            await _userManager.ResetPasswordAsync(user, resetPasswordDto.Token, resetPasswordDto.Password);

        if (!resetPasswordResult.Succeeded)
        {
            resetPasswordResult.Errors.ToList().ForEach(error =>
                ModelState.AddModelError(error.Code, error.Description));

            return BadRequest(ModelState);
        }

        return StatusCode(StatusCodes.Status200OK,
            new Response
            {
                Status = "Success",
                Message = $"Password has successfully been reset for account with email: {user.Email}"
            });
        ;
    }

    private JwtSecurityToken GenerateToken(IEnumerable<Claim> claims)
    {
        var authSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));

        var issuer = _configuration["Jwt:Issuer"];
        var audience = _configuration["Jwt:Audience"];
        var signingCredentials = new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(issuer, audience, claims, null, DateTime.Now.AddDays(7),
            signingCredentials);

        return token;
    }

    private async Task<JwtSecurityToken> GenerateAndReturnJwtToken(IdentityUser user)
    {
        // Claims list creation
        var authClaims = new List<Claim>
        {
            new(ClaimTypes.Name, user.UserName!),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        // Add roles to the claims list
        var userRoles = await _userManager.GetRolesAsync(user);

        userRoles.ToList().ForEach(
            role => authClaims.Add(new Claim(ClaimTypes.Role, role))
        );

        // Generate token with the claims
        var jwtToken = GenerateToken(authClaims);

        return jwtToken;
    }
}