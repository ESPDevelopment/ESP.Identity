using System.ComponentModel.DataAnnotations;

namespace ESP.Identity.Models.AccountViewModels
{
    public class ConfirmEmailViewModel : AccountViewModel
    {
        [Required]
        public string UserId { get; set; }

        [Required]
        public string Code { get; set; }
    }
}
