using System;
using System.Reflection;

namespace CSharpReflectionAdvancedPatterns
{
    class Program
    {
        static void AdvancedReflection(string name, string path, Type type, object[] args)
        {
            var asm = Assembly.Load(name);
            var asmFrom = Assembly.LoadFrom(path);
            var instance = Activator.CreateInstance(type);
            var withArgs = Activator.CreateInstance(type, args);
        }
    }
}
