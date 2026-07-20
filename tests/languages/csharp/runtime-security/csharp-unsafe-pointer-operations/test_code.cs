using System;
using System.Runtime.InteropServices;

namespace CSharpUnsafePointerOperations
{
    class Program
    {
        unsafe static void UnsafeOps(byte[] buffer, int size)
        {
            fixed (byte* ptr = buffer)
            {
                Span<byte> span = stackalloc byte[size];
                IntPtr native = Marshal.AllocHGlobal(size);
                Marshal.Copy(buffer, 0, native, size);
            }
        }
    }
}
