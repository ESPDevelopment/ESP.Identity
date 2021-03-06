﻿using System.Threading.Tasks;

namespace ESP.Identity.Services
{
    public interface IEmailSender
    {
        Task<bool> SendConfirmEmailAsync(string email, string confirmUrl);
        Task<bool> SendForgotPasswordEmailAsync(string email, string returnUrl);
    }
}
