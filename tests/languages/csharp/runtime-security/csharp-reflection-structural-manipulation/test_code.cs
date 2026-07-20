using System;
using System.Reflection;

namespace CSharpReflectionStructuralManipulation
{
    class Program
    {
        static void Mutate(object obj, PropertyInfo property, FieldInfo field, object value)
        {
            property.SetValue(obj, value);
            field.SetValue(obj, value);
            property.SetValue(obj, value, null);
        }
    }
}
