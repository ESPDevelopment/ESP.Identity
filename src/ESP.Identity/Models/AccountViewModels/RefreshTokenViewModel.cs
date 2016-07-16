using System.ComponentModel.DataAnnotations;

namespace ESP.Identity.Models.AccountViewModels
{
    public class RefreshTokenViewModel : AccountViewModel
    {
        [Required]
        public string AccessToken { get; set; }
        public string NewAccessToken { get; set; }
    }
}
