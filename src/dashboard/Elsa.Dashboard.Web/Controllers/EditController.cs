using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Elsa.Dashboard.Web.Models;
using Microsoft.AspNetCore.Authorization;

namespace Elsa.Dashboard.Web.Controllers
{
    public class EditController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public EditController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }


        [Authorize]
        public IActionResult Index()
        {

           

            return View();
        }

      


        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
