using System;

namespace CSharpReflectionTypeAssertionNegative
{
    class Program
    {
        static string TypeName(object obj)
        {
            return obj.GetType().Name;
        }
    }
}
