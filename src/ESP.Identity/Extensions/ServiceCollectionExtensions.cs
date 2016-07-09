using ESP.Identity.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace ESP.Identity.Extensions
{
    public static class ServiceCollectionExtensions
    {
        private const string TokenAudience = "http://espdevelopment.com";
        private const string TokenIssuer = "http://espdevelopment.com";

        public static IServiceCollection AddESPTokenKey(this IServiceCollection services, IConfigurationRoot configuration)
        {
            // Create security key
            RsaSecurityKey key = RSAKeyUtils.GetDecodedKey(configuration["TokenAuth:Secret"]);

            // Create token auth options
            TokenAuthOptions tokenAuthOptions = new TokenAuthOptions()
            {
                Audience = TokenAudience,
                Issuer = TokenIssuer,
                SigningKey = key,
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256Signature)
            };

            // Add token auth instance
            services.AddSingleton<TokenAuthOptions>(tokenAuthOptions);

            // Return result
            return services;
        }
    }
}
