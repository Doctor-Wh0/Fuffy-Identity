using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(Fuffy.Startup))]
namespace Fuffy
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
