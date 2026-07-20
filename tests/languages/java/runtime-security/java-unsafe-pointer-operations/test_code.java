package javaunsafepointeroperations;

import java.nio.ByteBuffer;
import sun.misc.Unsafe;

public class TestCode {
    public void unsafeOps(long size) throws Exception {
        Unsafe unsafe = Unsafe.getUnsafe();
        long address = unsafe.allocateMemory(size);
        unsafe.copyMemory(null, address, null, address, size);
        ByteBuffer buffer = ByteBuffer.allocateDirect((int) size);
        buffer.getLong(0);
    }
}
