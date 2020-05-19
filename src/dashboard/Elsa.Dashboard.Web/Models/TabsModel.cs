using System;
using System.Collections.Generic;

namespace Elsa.Dashboard.Web.Models
{
    public class TabsModel
    {
        public string Id { get; set; }

        public string Name { get; set; }

        public string Content { get; set; }

        //public string Name => !string.IsNullOrEmpty(RequestId);
    }

    public class ListTabsModel
    {
       
        public IList<TabsModel> List { get; set; }


        //public string Name => !string.IsNullOrEmpty(RequestId);
    }
}
