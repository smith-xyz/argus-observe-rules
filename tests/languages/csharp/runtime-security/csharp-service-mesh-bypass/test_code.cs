using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace CSharpServiceMeshBypass
{
    class Program
    {
        static async Task MeshBypass(HttpClient client, string serviceIp, string port)
        {
            var url = "http://" + serviceIp + ":" + port;
            await client.GetAsync(url);
        }

        static async Task EndpointBypass(HttpClient client, string endpoint)
        {
            var url = "http://" + endpoint;
            await client.GetStringAsync(url);
        }
    }
}
