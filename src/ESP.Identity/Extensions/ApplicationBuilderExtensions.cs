using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;

namespace ESP.Identity.Extensions
{
    public static class ApplicationBuilderExtensions
    {
        public static IApplicationBuilder UseESPCors(this IApplicationBuilder app)
        {
            // Eanble cross-origin requests
            app.UseCors(builder => builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());

            return app;
        }
    }
}
