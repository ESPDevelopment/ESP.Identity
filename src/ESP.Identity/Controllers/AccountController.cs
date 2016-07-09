using ESP.Identity.Models;
using ESP.Identity.Models.AccountViewModels;
using ESP.Identity.Security;
using ESP.Identity.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ESP.Identity.Controllers
{
    [RequireHttps]
    [Authorize]
    public class AccountController : Controller
    {
        private readonly IEmailSender _emailSender;
        private readonly ILogger _logger;
        private readonly ISmsSender _smsSender;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly TokenAuthOptions _tokenAuthOptions;
        private readonly UserManager<ApplicationUser> _userManager;

        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            TokenAuthOptions tokenAuthOptions,
            IEmailSender emailSender,
            ISmsSender smsSender,
            ILoggerFactory loggerFactory)
        {
            _signInManager = signInManager;
            _tokenAuthOptions = tokenAuthOptions;
            _userManager = userManager;
            _emailSender = emailSender;
            _smsSender = smsSender;
            _logger = loggerFactory.CreateLogger<AccountController>();
        }

        /// <summary>
        /// Changes the password for the currenc user's account
        /// </summary>
        /// <param name="model">ChangePasswordViewModel containing current password, new password, and password confirmation values.</param>
        /// <returns>
        /// (200) Ok - Account password change succeeded
        /// (400) Bad Request - Input values are not valid
        /// (409) Conflict - Account password change failed
        /// </returns>
        [HttpPost("api/v1/account/changePassword", Name = "PostChangePasswordRoute")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordViewModel model)
        {
            // Validate model
            if (!ModelState.IsValid)
            {
                if (model == null) model = new ChangePasswordViewModel();
                model.OldPassword = "***";
                model.NewPassword = "***";
                model.ConfirmPassword = "***";
                model.Succeeded = false;
                model.Message = "Invalid email address or password.";
                return BadRequest(model);
            }

            // Get currenct user
            var user = await GetCurrentUserAsync();
            if (user == null)
            {
                model.OldPassword = "***";
                model.NewPassword = "***";
                model.ConfirmPassword = "***";
                model.Succeeded = false;
                model.Message = "You must be logged in to change your password.";
                return StatusCode(409, model);
            }

            // Attempt to change password
            var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
            if (!result.Succeeded)
            {
                LogIdentityErrors(3, "PostChangePasswordRoute", result);
                AppendErrors(result, model);
                model.OldPassword = "***";
                model.NewPassword = "***";
                model.ConfirmPassword = "***";
                model.Succeeded = false;
                model.Message = "Unable to change password.";
                return StatusCode(409, model);
            }

            // Signin the user
            await _signInManager.SignInAsync(user, isPersistent: false);

            // Return success
            model.OldPassword = "***";
            model.NewPassword = "***";
            model.ConfirmPassword = "***";
            model.Succeeded = true;
            model.Message = "Password changed successfully.";
            return Ok(model);
        }

        /// <summary>
        /// Confirms the email address for a new account
        /// </summary>
        /// <param name="userId">User Id for the account to confirm</param>
        /// <param name="code">Confirmation code</param>
        /// <returns>
        /// (200) Ok - Account confirmation succeeded
        /// (400) Bad Request - Input values are not valid
        /// (409) Conflict - Account confirmation failed
        /// </returns>
        [HttpGet("api/v1/account/confirmEmail", Name = "GetConfirmEmailRoute")]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            // Validate input
            if (userId == null || code == null)
            {
                return BadRequest();
            }

            // Locate account to be validated
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return StatusCode(409);
            }

            // Confirm the account
            var result = await _userManager.ConfirmEmailAsync(user, code);
            if (!result.Succeeded)
            {
                return StatusCode(409);
            }

            return Ok();
        }

        /// <summary>
        /// Generate password recovery email
        /// </summary>
        /// <param name="model">ForgotPasswordViewModel containing email address and return Url value.</param>
        /// <returns>
        /// (200) Ok - Password recovery email generation succeeded
        /// (400) Bad Request - Input values not valid
        /// (409) Conflict - Password recovery email generation failed
        /// </returns>
        [HttpPost("api/v1/account/forgotPassword", Name = "PostForgotPasswordRoute")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordViewModel model)
        {
            // Validate the model
            if (!ModelState.IsValid)
            {
                if (model == null) model = new ForgotPasswordViewModel();
                model.Succeeded = false;
                model.Message = "Invalid email address.";
                return BadRequest(model);
            }

            // Locate account
            var user = await _userManager.FindByNameAsync(model.EmailAddress);
            if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
            {
                model.Succeeded = false;
                model.Message = "Unable to initiate password reset.";
                return StatusCode(409, model);
            }

            // Generate password reset token
            var code = await _userManager.GeneratePasswordResetTokenAsync(user);

            // Generate password reset uri
            List<KeyValuePair<string, string>> parameters = new List<KeyValuePair<string, string>>();
            parameters.Add(new KeyValuePair<string, string>("userId", user.Id));
            parameters.Add(new KeyValuePair<string, string>("code", code));
            QueryString queryString = QueryString.Create(parameters);
            var callbackUrl = model.ReturnUrl + queryString.ToUriComponent();

            // Send password recovery email
            await _emailSender.SendEmailAsync(
                model.EmailAddress,
                "Reset Password",
                $"Please reset your password by clicking here: <a href='{callbackUrl}'>link</a>. Here is the actual url: {callbackUrl}");

            // Return result
            model.Succeeded = true;
            return Ok(model);
        }

        /// <summary>
        /// Authenticates an existing user account
        /// </summary>
        /// <param name="model">LoginViewModel containing email address, password and remember me values.</param>
        /// <returns>
        /// (200) Ok - User authentication succeeded
        /// (400) Bad Request - Input values not valid
        /// (409) Conflict - User authentication failed
        /// </returns>
        [HttpPost("api/v1/account/login", Name = "PostLoginRoute")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginViewModel model)
        {
            // Validate the model
            if (!ModelState.IsValid)
            {
                if (model == null) model = new LoginViewModel();
                model.Password = "***";
                model.Succeeded = false;
                model.Message = "Invalid email address or password.";
                return BadRequest(model);
            }

            // Attempt to login the user
            var result = await _signInManager.PasswordSignInAsync(model.EmailAddress, model.Password, model.RememberMe, lockoutOnFailure: false);
            model.Succeeded = result.Succeeded;

            // Hide password
            model.Password = "***";

            // Process result
            if (result.Succeeded == false)
            {
                // Set appropriate error message
                if (result.IsLockedOut)
                {
                    model.Message = "This account has been locked out.";
                    return StatusCode(409, model);
                }
                if (result.IsNotAllowed)
                {
                    model.Message = "Signin for this account is not allowed";
                    return StatusCode(409, model);
                }
                if (result.RequiresTwoFactor)
                {
                    model.Message = "Signin for this account requires two-factor authentication.";
                    return StatusCode(409, model);
                }

                // Provide default error message
                model.Message = "Email address and password combination is not valid.";
                return StatusCode(409, model);
            }

            // Construct a security token string
            string token = await GetSecurityTokenAsString(model.EmailAddress);
            if (token.Equals(string.Empty))
            {
                model.Message = "An unexpected error occurred during sign in.";
                return BadRequest(model);
            }

            // Return the access token
            model.access_token = token;
            return Ok(model);
        }

        /// <summary>
        /// Logs off the user
        /// </summary>
        /// <returns>
        /// (200) Ok - Logoff succeeded
        /// </returns>
        [AllowAnonymous]
        [HttpPost("api/v1/account/logoff", Name = "PostLogoffRoute")]
        public async Task<IActionResult> LogOff()
        {
            // Logout the user
            await _signInManager.SignOutAsync();
            LogInformation(4, "PostLogoffRoute", "User logged out.");
            return Ok();
        }

        /// <summary>
        /// Registers a new account
        /// </summary>
        /// <param name="model">RegisterViewModel containing email address, password, and password confirmation values.</param>
        /// <returns>
        /// (200) Ok - New account was created successfully
        /// (400) Bad Request - Input values not valid
        /// (409) Conflict - New account could not be created
        /// </returns>
        [AllowAnonymous]
        [HttpPost("api/v1/account/register", Name = "PostRegisterRoute")]
        public async Task<IActionResult> Register([FromBody] RegisterViewModel model)
        {
            // Validate the model
            if (!ModelState.IsValid)
            {
                if (model == null) model = new RegisterViewModel();
                model.Succeeded = false;
                model.Message = "Invalid email address or password.";
                model.Password = "***";
                model.ConfirmPassword = "***";
                return BadRequest(model);
            }

            // Attempt to create a new account
            var user = new ApplicationUser { UserName = model.EmailAddress, Email = model.EmailAddress };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                AppendErrors(result, model);
                model.Succeeded = false;
                model.Message = "Registration failed.";
                model.Password = "***";
                model.ConfirmPassword = "***";
                return StatusCode(409, model);
            }

            // Generate email confirmation token
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            // Generate password reset uri
            List<KeyValuePair<string, string>> parameters = new List<KeyValuePair<string, string>>();
            parameters.Add(new KeyValuePair<string, string>("userId", user.Id));
            parameters.Add(new KeyValuePair<string, string>("code", code));
            QueryString queryString = QueryString.Create(parameters);
            var callbackUrl = model.ConfirmUrl + queryString.ToUriComponent();

            // Send confirmation email
            await _emailSender.SendEmailAsync(
                model.EmailAddress,
                "Confirm your account",
                $"Please confirm your account by clicking this link: <a href='{callbackUrl}'>link</a>. Here is the actual Url: {callbackUrl}");

            // Return result
            LogInformation(3, "PostRegisterRoute", "User created a new account with password.");
            model.Succeeded = true;
            model.Password = "***";
            model.ConfirmPassword = "***";
            return Ok(model);
        }

        /// <summary>
        /// Resets an account password
        /// </summary>
        /// <param name="model">ResetPasswordViewModel containing email address, password, password confirmation, and code values.</param>
        /// <returns>
        /// (200) Ok - Password reset succeeded
        /// (400) Bad Request - Input values not valid
        /// (409) Conflict - Password reset failed
        /// </returns>
        [HttpPost("api/v1/account/resetPassword", Name = "PostResetPasswordRoute")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            // Validate the model
            if (!ModelState.IsValid)
            {
                if (model == null) model = new ResetPasswordViewModel();
                model.Succeeded = false;
                model.Message = "Invalid email address, passwords, or reset code.";
                model.Password = "***";
                model.ConfirmPassword = "***";
                model.Code = "***";
                return BadRequest(model);
            }

            // Locate user account
            var user = await _userManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                model.Succeeded = false;
                model.Message = "Unable to reset password.";
                model.Password = "***";
                model.ConfirmPassword = "***";
                model.Code = "***";
                return StatusCode(409, model);
            }

            // Reset password
            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (!result.Succeeded)
            {
                LogIdentityErrors(3, "PostResetPasswordRoute", result);
                AppendErrors(result, model);
                model.Succeeded = false;
                model.Message = "Unable to reset password.";
                model.Password = "***";
                model.ConfirmPassword = "***";
                model.Code = "***";
                return StatusCode(409, model);
            }

            // Return result
            model.Succeeded = true;
            model.Password = "***";
            model.ConfirmPassword = "***";
            model.Code = "***";
            return Ok(model);
        }

        /// <summary>
        /// Tests the email send capability
        /// </summary>
        /// <returns>
        /// (200) Ok - User authentication succeeded
        /// </returns>
        [HttpGet("api/v1/account/sendEmailTest", Name = "SendEmailTestRoute")]
        [AllowAnonymous]
        public async Task<IActionResult> SendEmailTest()
        {
            string emailAddress = "rickm@espdevelopment.com";
            await _emailSender.SendEmailAsync(emailAddress,
                    "Email Send Test",
                    $"This is a test of the email sending capability.");
            return Ok();
        }

        #region Helpers

        /// <summary>
        /// Append identity errors to the view model
        /// </summary>
        /// <param name="result">IdentityResult object</param>
        /// <param name="model">An AccountViewModel object</param>
        private void AppendErrors(IdentityResult result, AccountViewModel model)
        {
            // Append errors to the request model
            if (result != null && result.Errors != null)
            {
                model.Errors = new List<IdentityError>();
                foreach (IdentityError error in result.Errors)
                {
                    model.Errors.Add(error);
                }
            }
        }

        /// <summary>
        /// Return the current user
        /// </summary>
        /// <returns>The current user</returns>
        private Task<ApplicationUser> GetCurrentUserAsync()
        {
            return _userManager.GetUserAsync(HttpContext.User);
        }

        /// <summary>
        /// Constructs a JWT security token for the specified username and returns it as
        /// a base-64 encoded string that can be used in an Authorization header.
        /// </summary>
        /// <param name="username">Unique identifier for the user</param>
        /// <returns>A base-64 encoded JWT token if successful, otherwise and empty string</returns>
        private async Task<string> GetSecurityTokenAsString(string username)
        {
            // Retrieve the application user from the identity store
            ApplicationUser user = await _userManager.FindByNameAsync(username);
            if (user == null)
            {
                return string.Empty;
            }

            // Construct an identity with appropriate claims
            IList<Claim> claims = await _userManager.GetClaimsAsync(user);
            if (claims == null)
            {
                return string.Empty;
            }
            claims.Add(new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", user.Id));
            claims.Add(new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", user.Email));
            ClaimsIdentity identity = new ClaimsIdentity(claims);
            if (identity == null)
            {
                return string.Empty;
            }

            // Create security token
            DateTime issuedAt = DateTime.UtcNow;
            JwtSecurityToken securityToken = new JwtSecurityToken(
                issuer: _tokenAuthOptions.Issuer,
                audience: _tokenAuthOptions.Audience,
                signingCredentials: _tokenAuthOptions.SigningCredentials,
                claims: claims,
                notBefore: issuedAt,
                expires: issuedAt.AddHours(2));
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();

            return handler.WriteToken(securityToken);
        }

        /// <summary>
        /// Log identity action errors
        /// </summary>
        /// <param name="eventId">The event id associated with the error.</param>
        /// <param name="routeName">The name of the route in which the error occurred.</param>
        /// <param name="result">An IdentityResult object.</param>
        private void LogIdentityErrors(int eventId, string routeName, IdentityResult result)
        {
            string uri = Url.RouteUrl(routeName);
            foreach (var error in result.Errors)
            {
                _logger.LogInformation(eventId, "[" + uri + "] " + error.Description);
            }
        }

        /// <summary>
        /// Log information message
        /// </summary>
        /// <param name="eventId">The event id associated with the message.</param>
        /// <param name="routeName">The name of the route from which the message originated.</param>
        /// <param name="message">The message to be logged.</param>
        private void LogInformation(int eventId, string routeName, string message)
        {
            string uri = Url.RouteUrl(routeName);
            _logger.LogInformation(eventId, "[" + uri + "] " + message);
        }

        #endregion
    }
}
