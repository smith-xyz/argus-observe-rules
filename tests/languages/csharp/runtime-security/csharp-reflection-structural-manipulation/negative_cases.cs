using System;

namespace CSharpReflectionStructuralManipulationNegative
{
    class Program
    {
        static object Read(object obj, string name)
        {
            return obj.GetType().GetProperty(name)?.GetValue(obj);
        }
    }
}
