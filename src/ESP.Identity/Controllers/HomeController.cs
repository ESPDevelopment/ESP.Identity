﻿using Microsoft.AspNetCore.Mvc;

namespace ESP.Identity.Controllers
{
    [RequireHttps]
    public class HomeController : Controller
    {
        public IActionResult Error()
        {
            return View();
        }
    }
}
