using System;

namespace CSharpReflectionBasicUsageNegative
{
    class Program
    {
        static int ObjectHash(object obj)
        {
            return obj.GetHashCode();
        }
    }
}
