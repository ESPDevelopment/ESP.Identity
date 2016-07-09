using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ESP.Identity.Data;
using ESP.Identity.Extensions;
using ESP.Identity.Models;
using ESP.Identity.Services;

namespace ESP.Identity
{
    public class Startup
    {
        public IConfigurationRoot Configuration { get; }

        public Startup(IHostingEnvironment env)
        {
            // Initialize configuration builder
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true);

            // Configure development resources, if necessary
            if (env.IsDevelopment())
            {
                builder.AddUserSecrets();
            }

            // Add environment variables
            builder.AddEnvironmentVariables();

            // Build configuration
            Configuration = builder.Build();
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Add database context
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(Configuration.GetConnectionString("IdentityConnection")));

            // Add identity
            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            // Require SSL connection
            services.Configure<MvcOptions>(options =>
            {
                options.Filters.Add(new RequireHttpsAttribute());
            });

            // Add MVC
            services.AddMvc();

            // Add CORS support
            services.AddCors();

            // Add application services
            services.AddTransient<IEmailSender, AuthMessageSender>();
            services.AddTransient<ISmsSender, AuthMessageSender>();
            services.Configure<AuthMessageSenderOptions>(Configuration);

            // Add configuration singleton
            services.AddSingleton(Configuration);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            // Configure logging
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();

            // Configure exception handling
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            // Configure static files
            app.UseStaticFiles();

            // Ensure databases have been migrated and properly seeded
            using (var serviceScope = app.ApplicationServices.GetRequiredService<IServiceScopeFactory>()
                .CreateScope())
            {
                serviceScope.ServiceProvider.GetService<ApplicationDbContext>()
                    .Database.Migrate();
            }

            // Configure identity service
            app.UseIdentity();

            // Use ESP-specific CORS
            app.UseESPCors();

            // Configure MVC
            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
