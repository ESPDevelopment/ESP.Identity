using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Logging;
using ESP.Identity.Models;
using ESP.Identity.Models.AccountViewModels;
using ESP.Identity.Services;

namespace ESP.Identity.Controllers
{
    [RequireHttps]
    [Authorize]
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly ISmsSender _smsSender;
        private readonly ILogger _logger;

        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IEmailSender emailSender,
            ISmsSender smsSender,
            ILoggerFactory loggerFactory)
        {
            _userManager = userManager;
            _signInManager = signInManager;
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
                LogModelErrors(3, "PostChangePasswordRoute");
                return BadRequest(ModelState);
            }

            // Get currency user
            var user = await GetCurrentUserAsync();
            if (user == null)
            {
                LogInformation(3, "PostChangePasswordRoute", "");
                return StatusCode(409);
            }

            // Attempt to change password
            var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
            if (!result.Succeeded)
            {
                AddIdentityErrors(result);
                LogIdentityErrors(3, "PostChangePasswordRoute", result);
                return StatusCode(409);
            }
            LogInformation(3, "PostChangePasswordRoute", "User changed their password successfully.");

            // Signin the user
            await _signInManager.SignInAsync(user, isPersistent: false);

            // Return success
            return Ok();
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
                LogModelErrors(1, "PostForgotPasswordRoute");
                return BadRequest(ModelState);
            }

            // Locate account
            var user = await _userManager.FindByNameAsync(model.Email);
            if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
            {
                return StatusCode(409);
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
                model.Email,
                "Reset Password",
                $"Please reset your password by clicking here: <a href='{callbackUrl}'>link</a>. Here is the actual url: {callbackUrl}");

            // Return result
            return Ok();
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
                LogModelErrors(1, "PostLoginRoute");
                return BadRequest(ModelState);
            }

            // Attempt to login the user
            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);

            // Return success
            if (result.Succeeded)
            {
                LogInformation(1, "PostLoginRoute", "User authentication succeeded.");
                return Ok();
            }

            // Return failure
            if (result.IsLockedOut)
            {
                LogInformation(2, "PostLoginRoute", "User account locked out.");
                return StatusCode(409, ModelState);
            }
            else
            {
                LogInformation(2, "PostLoginRoute", "User authentication failed.");
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return StatusCode(409, ModelState);
            }
        }

        /// <summary>
        /// Logs off the user
        /// </summary>
        /// <returns>
        /// (200) Ok - Logoff succeeded
        /// </returns>
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
                LogModelErrors(3, "PostRegisterRoute");
                return BadRequest(ModelState);
            }

            // Attempt to create a new account
            var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                AddIdentityErrors(result);
                LogIdentityErrors(3, "PostRegisterRoute", result);
                return StatusCode(409, ModelState);
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
                model.Email,
                "Confirm your account",
                $"Please confirm your account by clicking this link: <a href='{callbackUrl}'>link</a>. Here is the actual Url: {callbackUrl}");

            // Return result
            LogInformation(3, "PostRegisterRoute", "User created a new account with password.");
            return Ok();
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
                LogModelErrors(3, "PostResetPasswordRoute");
                return BadRequest(ModelState);
            }

            // Locate user account
            var user = await _userManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                return StatusCode(409);
            }

            // Reset password
            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (!result.Succeeded)
            {
                AddIdentityErrors(result);
                LogIdentityErrors(3, "PostResetPasswordRoute", result);
                return StatusCode(409, ModelState);
            }

            // Return result
            return Ok();
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
        /// Add identity action errors
        /// </summary>
        /// <param name="result">Identity action result</param>
        private void AddIdentityErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
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

        /// <summary>
        /// Log model state errors
        /// </summary>
        /// <param name="eventId">The event id associated with the message.</param>
        /// <param name="routeName">The name of the route in which the error occurred.</param>
        private void LogModelErrors(int eventId, string routeName)
        {
            string uri = Url.RouteUrl(routeName);
            foreach (var error in ModelState.Values)
            {
                foreach (var message in error.Errors)
                {
                    _logger.LogInformation(eventId, "[" + uri + "] " + message.ErrorMessage);
                }
            }
        }

        #endregion
    }
}
