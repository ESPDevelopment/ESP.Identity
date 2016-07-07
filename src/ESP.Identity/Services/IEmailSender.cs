﻿using System.Threading.Tasks;

namespace ESP.Identity.Services
{
    public interface IEmailSender
    {
        Task SendEmailAsync(string email, string subject, string message);
    }
}