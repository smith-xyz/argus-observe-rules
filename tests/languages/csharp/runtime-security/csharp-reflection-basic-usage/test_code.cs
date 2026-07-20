using System;

namespace CSharpReflectionBasicUsage
{
    class Program
    {
        static void Inspect(object obj, string name)
        {
            var t = typeof(string);
            var runtime = obj.GetType();
            var loaded = Type.GetType(name);
            var prop = t.GetProperty("Length");
            var field = t.GetField("Empty");
            var method = t.GetMethod("Concat");
        }
    }
}
