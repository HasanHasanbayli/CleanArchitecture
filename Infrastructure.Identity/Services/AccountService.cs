using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Application.DTOs.Account;
using Application.DTOs.Email;
using Application.Enums;
using Application.Exceptions;
using Application.Interfaces;
using Application.Wrappers;
using Domain.Settings;
using Infrastructure.Identity.Helpers;
using Infrastructure.Identity.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Infrastructure.Identity.Services;

public class AccountService : IAccountService
{
    private readonly IEmailService _emailService;
    private readonly JwtSettings _jwtSettings;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;

    public AccountService(UserManager<ApplicationUser> userManager,
        IOptions<JwtSettings> jwtSettings,
        SignInManager<ApplicationUser> signInManager,
        IEmailService emailService)
    {
        _userManager = userManager;
        _jwtSettings = jwtSettings.Value;
        _signInManager = signInManager;
        _emailService = emailService;
    }

    public async Task<Response<AuthenticationResponse>> AuthenticateAsync(AuthenticationRequest request,
        string ipAddress)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);

        if (user == null) throw new ApiException($"No Accounts Registered with {request.Email}.");

        var result =
            await _signInManager.PasswordSignInAsync(user.UserName, request.Password, false, false);

        if (!result.Succeeded) throw new ApiException($"Invalid Credentials for '{request.Email}'.");

        if (!user.EmailConfirmed) throw new ApiException($"Account Not Confirmed for '{request.Email}'.");

        var rolesList = await _userManager.GetRolesAsync(user).ConfigureAwait(false);

        var jwtSecurityToken = await GenerateJwToken(user);

        var refreshToken = GenerateRefreshToken(ipAddress);

        var response = new AuthenticationResponse
        {
            Id = user.Id,
            JwToken = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
            Email = user.Email,
            UserName = user.UserName,
            Roles = rolesList.ToList(),
            IsVerified = user.EmailConfirmed,
            RefreshToken = refreshToken.Token
        };

        return new Response<AuthenticationResponse>(response, true, $"Authenticated {user.UserName}");
    }

    public async Task<Response<string>> RegisterAsync(RegisterRequest request, string origin)
    {
        var userWithSameUserName = await _userManager.FindByNameAsync(request.UserName);

        if (userWithSameUserName != null) throw new ApiException($"Username '{request.UserName}' is already taken.");

        var user = new ApplicationUser
        {
            Email = request.Email,
            FirstName = request.FirstName,
            LastName = request.LastName,
            UserName = request.UserName
        };

        var userWithSameEmail = await _userManager.FindByEmailAsync(request.Email);

        if (userWithSameEmail != null) throw new ApiException($"Email {request.Email} is already registered.");

        var result = await _userManager.CreateAsync(user, request.Password);

        if (!result.Succeeded) throw new ApiException($"{result.Errors}");

        await _userManager.AddToRoleAsync(user, Roles.Basic.ToString());

        var verificationUri = await SendVerificationEmail(user, origin);

        await _emailService.SendAsync(new EmailRequest
        {
            From = "hasanhasanbeyli@gmail.com", To = user.Email,
            Body = $"Please confirm your account by visiting this URL {verificationUri}",
            Subject = "Confirm Registration"
        });

        return new Response<string>(user.Id, true,
            $"User Registered. Please confirm your account by visiting this URL {verificationUri}");
    }

    public async Task<Response<string>> ConfirmEmailAsync(string userId, string code)
    {
        var user = await _userManager.FindByIdAsync(userId);

        code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));

        var result = await _userManager.ConfirmEmailAsync(user, code);

        if (!result.Succeeded) throw new ApiException($"An error occured while confirming {user.Email}.");

        return new Response<string>(user.Id, true,
            $"Account Confirmed for {user.Email}. You can now use the /api/Account/authenticate endpoint.");
    }

    public async Task ForgotPassword(ForgotPasswordRequest model, string origin)
    {
        var account = await _userManager.FindByEmailAsync(model.Email);

        // always return ok response to prevent email enumeration
        if (account == null) return;

        var code = await _userManager.GeneratePasswordResetTokenAsync(account);

        const string route = "api/account/reset-password/";

        var endpointUri = new Uri(string.Concat($"{origin}/", route));

        var emailRequest = new EmailRequest
        {
            Body = $"You reset token is - {code}",
            To = model.Email,
            Subject = "Reset Password"
        };

        await _emailService.SendAsync(emailRequest);
    }

    public async Task<Response<string>> ResetPassword(ResetPasswordRequest model)
    {
        var account = await _userManager.FindByEmailAsync(model.Email);

        if (account == null) throw new ApiException($"No Accounts Registered with {model.Email}.");

        var result = await _userManager.ResetPasswordAsync(account, model.Token, model.Password);

        if (!result.Succeeded) throw new ApiException("Error occured while reseting the password.");

        return new Response<string>(model.Email!, true, "Password Resetted.");
    }

    private async Task<JwtSecurityToken> GenerateJwToken(ApplicationUser user)
    {
        var userClaims = await _userManager.GetClaimsAsync(user);

        var roles = await _userManager.GetRolesAsync(user);

        var roleClaims = roles.Select(t => new Claim("roles", t)).ToList();

        var ipAddress = IpHelper.GetIpAddress();

        var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id),
                new Claim("ip", ipAddress)
            }
            .Union(userClaims)
            .Union(roleClaims);

        var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key!));

        var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

        var jwtSecurityToken = new JwtSecurityToken(
            _jwtSettings.Issuer,
            _jwtSettings.Audience,
            claims,
            expires: DateTime.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes),
            signingCredentials: signingCredentials);

        return jwtSecurityToken;
    }

    private RefreshToken GenerateRefreshToken(string ipAddress)
    {
        return new RefreshToken
        {
            Token = RandomTokenString(),
            Expires = DateTime.UtcNow.AddDays(7),
            Created = DateTime.UtcNow,
            CreatedByIp = ipAddress
        };
    }

    private string RandomTokenString()
    {
        using var rngCryptoServiceProvider = new RNGCryptoServiceProvider();

        var randomBytes = new byte[40];

        rngCryptoServiceProvider.GetBytes(randomBytes);

        // convert random bytes to hex string
        return BitConverter.ToString(randomBytes).Replace("-", "");
    }

    private async Task<string> SendVerificationEmail(ApplicationUser user, string origin)
    {
        var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);

        code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

        const string route = "api/account/confirm-email/";

        var endpointUri = new Uri(string.Concat($"{origin}/", route));

        var verificationUri = QueryHelpers.AddQueryString(endpointUri.ToString(), "userId", user.Id);

        verificationUri = QueryHelpers.AddQueryString(verificationUri, "code", code);

        //Email Service Call Here
        return verificationUri;
    }
}