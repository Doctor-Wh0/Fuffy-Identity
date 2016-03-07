using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(IZ10.Startup))]
namespace IZ10
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
