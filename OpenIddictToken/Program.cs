
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore;

namespace OpenIddictToken
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var newHost = WebHost
                .CreateDefaultBuilder(args)
                .UseStartup<Startup>()
                .Build();

            newHost.Run();
        }
    }
}
