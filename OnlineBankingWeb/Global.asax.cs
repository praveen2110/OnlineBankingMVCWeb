using OnlineBanking.DAL;
using System.Web;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;

namespace OnlineBankingWeb
{
    public class MvcApplication : HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();            
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
            OnlineBanking.BusinessProcess.DatabaseInitializer dbInit = new OnlineBanking.BusinessProcess.DatabaseInitializer();
            dbInit.InitializeDatabase(new BankContext());
        }
    }
}
