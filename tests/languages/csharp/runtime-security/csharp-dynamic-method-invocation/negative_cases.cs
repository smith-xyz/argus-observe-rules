using System;

namespace CSharpDynamicMethodInvocationNegative
{
    class Sample
    {
        public string Run() => "ok";
    }

    class Program
    {
        static string CallDirect(Sample obj)
        {
            return obj.Run();
        }
    }
}
