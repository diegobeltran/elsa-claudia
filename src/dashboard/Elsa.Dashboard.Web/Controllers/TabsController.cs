using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Elsa.Dashboard.Web.Models;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling MVC for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Elsa.Dashboard.Web.Controllers
{

    public class TabsController : Controller
    {
        // GET: /<controller>/ 
        [HttpGet("Tabs")]
        public IActionResult Tabs()
        {
            List<TabsModel> list = new List<TabsModel>();

            list.Add(new TabsModel { Id="1", Name="test1" });

            list.Add(new TabsModel { Id = "1", Name = "test2" });

            ListTabsModel a = new ListTabsModel();

            a.List = list;

            return PartialView(a);
        }
    }
}
