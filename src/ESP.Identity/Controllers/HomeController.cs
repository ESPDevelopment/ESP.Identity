using ESP.Identity.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SendGrid;
using System;
using System.Net.Mail;
using System.Threading.Tasks;

namespace ESP.Identity.Controllers
{
    [RequireHttps]
    public class HomeController : Controller
    {
        private readonly ILogger _logger;

        public HomeController(ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger<AccountController>();
        }

        public IActionResult Error()
        {
            return View();
        }
    }
}
