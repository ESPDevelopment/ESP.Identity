using Microsoft.AspNetCore.Builder;

namespace ESP.Identity.Extensions
{
    public static class ApplicationBuilderExtensions
    {
        public static IApplicationBuilder UseESPCors(this IApplicationBuilder app)
        {
            // Eanble cross-origin requests
            string[] exposedHeaders = {};
            app.UseCors(builder => builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader().WithExposedHeaders(exposedHeaders));

            return app;
        }
    }
}
