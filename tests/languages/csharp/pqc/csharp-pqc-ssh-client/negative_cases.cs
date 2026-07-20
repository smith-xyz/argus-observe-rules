using System;

namespace CSharpPqcSshClientNegative
{
    class Program
    {
        static string SshCommand(string host, string user)
        {
            return $"ssh {user}@{host}";
        }
    }
}
