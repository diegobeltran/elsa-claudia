using System;
using app.Areas.Identity.Data;
using app.Data;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

[assembly: HostingStartup(typeof(app.Areas.Identity.IdentityHostingStartup))]
namespace app.Areas.Identity
{
    public class IdentityHostingStartup : IHostingStartup
    {
        public void Configure(IWebHostBuilder builder)
        {
            builder.ConfigureServices((context, services) => {
                services.AddDbContext<appContext>(options =>
                    options.UseSqlite(
                        context.Configuration.GetConnectionString("appContextConnection")));

                services.AddDefaultIdentity<appUser>(options => options.SignIn.RequireConfirmedAccount = true)
                    .AddEntityFrameworkStores<appContext>();
            });
        }
    }
}