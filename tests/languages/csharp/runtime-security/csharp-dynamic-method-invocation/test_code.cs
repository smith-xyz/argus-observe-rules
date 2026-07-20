using System;
using System.Reflection;

namespace CSharpDynamicMethodInvocation
{
    class Program
    {
        static object CallDynamic(object obj, Type type, string name, object[] args)
        {
            var method = type.GetMethod(name);
            var direct = method.Invoke(obj, args);
            var resolved = type.GetMethod(name);
            return resolved.Invoke(obj, args);
        }
    }
}
