using System;

namespace CSharpReflectionTypeAssertion
{
    class Program
    {
        static void CheckTypes(object obj, Type type, Type other)
        {
            var isString = obj is string;
            var assignable = type.IsAssignableFrom(other);
            var instance = type.IsInstanceOfType(obj);
        }
    }
}
