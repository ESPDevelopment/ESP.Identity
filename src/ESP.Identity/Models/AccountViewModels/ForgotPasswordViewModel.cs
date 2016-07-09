using System.ComponentModel.DataAnnotations;

namespace ESP.Identity.Models.AccountViewModels
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [Url]
        public string ReturnUrl { get; set; }
    }
}
