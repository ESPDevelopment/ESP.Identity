using System.ComponentModel.DataAnnotations;

namespace ESP.Identity.Models.AccountViewModels
{
    public class ResendConfirmationViewModel : AccountViewModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string EmailAddress { get; set; }

        [Required]
        [Url]
        public string ConfirmUrl { get; set; }
    }
}
