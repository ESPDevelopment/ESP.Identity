using System.ComponentModel.DataAnnotations;

namespace ESP.Identity.Models.AccountViewModels
{
    public class ForgotPasswordViewModel : AccountViewModel
    {
        [Required]
        [EmailAddress]
        public string EmailAddress { get; set; }

        [Required]
        [Url]
        public string ReturnUrl { get; set; }
    }
}
