using System;
using System.IdentityModel.Tokens.Jwt;
using Elsa.Dashboard.Web.Areas.Identity.Data;
using Elsa.Dashboard.Web.Data;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using YesSql.Services;

[assembly: HostingStartup(typeof(Elsa.Dashboard.Web.Areas.Identity.IdentityHostingStartup))]
namespace Elsa.Dashboard.Web.Areas.Identity
{
    public class IdentityHostingStartup : IHostingStartup
    {
        public void Configure(IWebHostBuilder builder)
        {
            builder.ConfigureServices((context, services) => {
                services.AddDbContext<ElsaDashboardWebContext>(options =>
                    options.UseSqlServer(
                        context.Configuration.GetConnectionString("ElsaDashboardWebContextConnection")));

                services.AddDefaultIdentity<ElsaDashboardWebUser>(options => options.SignIn.RequireConfirmedAccount = false)
                    .AddEntityFrameworkStores<ElsaDashboardWebContext>();
                //    .AddDefaultTokenProviders();



                //services.Configure<IdentityOptions>(options =>
                //{
                //    // Password settings.
                //    options.Password.RequireDigit = true;
                //    options.Password.RequireLowercase = true;
                //    options.Password.RequireNonAlphanumeric = true;
                //    options.Password.RequireUppercase = true;
                //    options.Password.RequiredLength = 6;
                //    options.Password.RequiredUniqueChars = 1;

                //    // Lockout settings.
                //    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
                //    options.Lockout.MaxFailedAccessAttempts = 5;
                //    options.Lockout.AllowedForNewUsers = true;

                //    // User settings.
                //    options.User.AllowedUserNameCharacters =
                //    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
                //    options.User.RequireUniqueEmail = false;
                //});

                //services.ConfigureApplicationCookie(options =>
                //{
                //    // Cookie settings
                //    options.Cookie.HttpOnly = true;
                //    options.ExpireTimeSpan = TimeSpan.FromMinutes(5);

                //    options.LoginPath = "/Identity/Account/Login";
                //    options.AccessDeniedPath = "/Identity/Account/AccessDenied";
                //    options.SlidingExpiration = true;

                //});

                


            });
        }
    }
}