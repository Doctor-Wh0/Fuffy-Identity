using Microsoft.AspNet.Identity;
using System.Web.Mvc;
using System.Threading;
using System.Linq;
using System.Security.Claims;

namespace IZ10.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
        [Authorize]
        public ActionResult Profile()
        {
            var user = HttpContext.User.Identity.GetUserName();

            var identity = (ClaimsPrincipal)Thread.CurrentPrincipal;
            var email = HttpContext.User.Identity.Name;
            var name = identity.Claims.Where(c => c.Type == ClaimTypes.GivenName).Select(c => c.Value).SingleOrDefault();
            var secondname = identity.Claims.Where(c => c.Type == "SecondName").Select(c => c.Value).SingleOrDefault();
            var city = identity.Claims.Where(c => c.Type == "city").Select(c => c.Value).SingleOrDefault();
            string Data = "Эл. адрес: " + email + "Имя:" + name + "Город:" + city + "</p>" + User.Identity.GetUserId();
            ViewBag.Name = name;
            ViewBag.SecondName = secondname;
            ViewBag.data = Data;
          
            return View();
        }

    }
}