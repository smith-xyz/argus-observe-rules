using System.Reflection;

namespace CSharpReflectionValueMutation
{
    class Program
    {
        static void MutateValues(object obj, PropertyInfo property, FieldInfo field, object value)
        {
            property.SetValue(obj, value);
            field.SetValue(obj, value);
        }
    }
}
