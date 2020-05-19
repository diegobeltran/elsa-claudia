using Elsa.Activities.Email.Extensions;
using Elsa.Activities.Http.Extensions;
using Elsa.Activities.Timers.Extensions;
using Elsa.Dashboard.ActionFilters;
using Elsa.Dashboard.Extensions;
using Elsa.Persistence.EntityFrameworkCore.DbContexts;
using Elsa.Persistence.EntityFrameworkCore.Extensions;
using Elsa.Persistence.MongoDb.Extensions;
using Elsa.Persistence.YesSql.Extensions;
using IdentityServer4.AccessTokenValidation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using YesSql;
using YesSql.Provider.Sqlite;
using YesSql.Provider.SqlServer;

namespace Elsa.Dashboard.Web
{
    public class AuthorizationConsts
    {
        public const string BearerOrCookiesAuthenticationScheme = CookieAuthenticationDefaults.AuthenticationScheme + "," + IdentityServerAuthenticationDefaults.AuthenticationScheme;
        public const string IdentityProviderClaimType = "idp";
        public const string ScopeClaimType = "scope";
        public const string ReadPolicy = "RequireReadPolicy";
        public const string ReadScope = "data:read";
    }

    public class Startup
    {
        public Startup(Microsoft.Extensions.Configuration.IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public Microsoft.Extensions.Configuration.IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            var elsaSection = Configuration.GetSection("Elsa");
            
            services
                // Add workflow services.
                //.AddElsa(x => x.AddMongoDbStores(Configuration, "Elsa", "MongoDb"))
                //.AddElsa()
                //.AddElsa(elsa => elsa.AddEntityFrameworkStores<SqlServerContext>(ef => ef.UseSqlServer(Configuration.GetConnectionString("SqlServer"))))
                .AddElsa(
                    elsa => elsa.AddYesSqlStores(
                        options => options
                            .UseSqlServer(
                                Configuration.GetConnectionString("YesSql"),
                                IsolationLevel.ReadCommitted)
                            .UseDefaultIdGenerator()
                            .SetTablePrefix("elsa_")))
                // Add activities we'd like to use.
                // Configuring the activities as is done here is only required if we want to be able to actually run workflows form this application.
                // Otherwise it's only necessary to register activities for the workflow designer to discover.
                .AddHttpActivities(options => options.Bind(elsaSection.GetSection("Http")))
                .AddEmailActivities(options => options.Bind(elsaSection.GetSection("Smtp")))
                .AddTimerActivities(options => options.Bind(elsaSection.GetSection("Timers")))
                
                // Add Dashboard services.
                .AddElsaDashboard()
                .AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

            services.AddSession(options => {
                options.IdleTimeout = TimeSpan.FromMinutes(8640); //Sessions Time
            });

            services.AddMvc(options =>
            {
                options.Filters.Add(new LocalhostFilter());
            });

            services.AddRazorPages()
                
            .AddRazorRuntimeCompilation();
            //services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            //services.AddAuthentication(options => {
            //    options.DefaultAuthenticateScheme = "JwtBearer";
            //    options.DefaultChallengeScheme = "JwtBearer";
            //})
            //services.AddAuthentication(options =>
            //{
            //    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            //    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;

            //})
            //.AddJwtBearer(options =>
            //    {
            //        options.TokenValidationParameters = new TokenValidationParameters()
            //        {
            //            ValidateIssuer = true,
            //            ValidateAudience = true,
            //            ValidateLifetime = true,
            //            ValidateIssuerSigningKey = true,
            //            ValidIssuer = Configuration["JWT:Issuer"],
            //            ValidAudience = Configuration["JWT:Audience"],
            //            IssuerSigningKey = new SymmetricSecurityKey(
            //                Encoding.UTF8.GetBytes(Configuration["JWT:ClaveSecreta"])
            //            )
            //        };
            //    });




            services.AddCors();

            // Add authentication before adding MVC
            // Add JWT and Azure AD (that uses OpenIdConnect) and cookies.
            // Use a smart policy scheme to choose the correct authentication scheme at runtime
            //services
            //    .AddAuthentication(sharedOptions =>
            //    {
            //        sharedOptions.DefaultScheme = "smart";
            //        sharedOptions.DefaultChallengeScheme = "smart";
            //    })
            //    .AddPolicyScheme("smart", "Authorization Bearer or OIDC", options =>
            //    {
            //        options.ForwardDefaultSelector = context =>
            //        {
            //            var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
            //            if (authHeader?.StartsWith("Bearer ") == true)
            //            {
            //                return JwtBearerDefaults.AuthenticationScheme;
            //            }
            //            return IdentityServerAuthenticationDefaults.AuthenticationScheme;
            //        };
            //    })
            //   .AddJwtBearer(options =>
            //    {
            //        options.TokenValidationParameters = new TokenValidationParameters()
            //        {
            //            ValidateIssuer = true,
            //            ValidateAudience = true,
            //            ValidateLifetime = true,
            //            ValidateIssuerSigningKey = true,
            //            ValidIssuer = Configuration["JWT:Issuer"],
            //            ValidAudience = Configuration["JWT:Audience"],
            //            IssuerSigningKey = new SymmetricSecurityKey(
            //                Encoding.UTF8.GetBytes(Configuration["JWT:ClaveSecreta"])
            //            )
            //        };
            //    });
                //.AddIdentityCookies(options =>
                //{
                //    options.ApplicationCookie.Configure(o => o.LoginPath = "/Identity/Account/Login"

                //    ) ;  
                    
                //})
                //;


            //services
            //    .AddMvc(config =>
            //    {
            //        var policy = new AuthorizationPolicyBuilder()
            //                         .RequireAuthenticatedUser()
            //                         .Build();
            //        // Authentication is required by default
            //        config.Filters.Add(new AuthorizeFilter(policy));
            //        config.RespectBrowserAcceptHeader = true;
            //    });


            // ===== Add Jwt Authentication ========
            //JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear(); // => remove default claims
            //services
            //    .AddAuthentication(options =>
            //    {
            //        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            //        options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            //        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            //        options.DefaultAuthenticateScheme = IdentityServerAuthenticationDefaults.AuthenticationScheme;
            //        options.DefaultScheme = IdentityServerAuthenticationDefaults.AuthenticationScheme;
            //        options.DefaultChallengeScheme = IdentityServerAuthenticationDefaults.AuthenticationScheme;


            //    })
            //    .AddJwtBearer(cfg =>
            //    {
            //        cfg.RequireHttpsMetadata = false;
            //        cfg.SaveToken = true;
            //        cfg.TokenValidationParameters = new TokenValidationParameters
            //        {
            //            ValidIssuer = Configuration["JwtIssuer"],
            //            ValidAudience = Configuration["JwtIssuer"],
            //            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["JwtKey"])),
            //            ClockSkew = TimeSpan.Zero // remove delay of token when expire
            //        };
            //    })
            //    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);

            services.AddAuthentication();


            //services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment()) 
                app.UseDeveloperExceptionPage();

            app
                // This is only necessary if we want to be able to run workflows containing HTTP activities from this application. 
                .UseHttpActivities()

                .UseStaticFiles()
                .UseRouting();
                //.UseEndpoints(endpoints => endpoints.MapControllers());
            //.UseWelcomePage();

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseSession();


            app.UseAuthentication();
            app.UseCookiePolicy();


            app.UseRouting();

            app.UseAuthorization();

            

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapRazorPages();
                endpoints.MapControllers();
            });

            //Add-Migration app

        }
    }
}