using System;

namespace CSharpUnsafePointerOperationsNegative
{
    class Program
    {
        static int SafeLen(byte[] data)
        {
            return data.Length;
        }
    }
}
