use std::ptr;

fn unsafe_ops(buf: *const u8, len: usize) {
    unsafe {
        let _val = ptr::read(buf);
        ptr::write(buf as *mut u8, 0);
        let _slice = std::slice::from_raw_parts(buf, len);
        let _mut_slice = std::slice::from_raw_parts_mut(buf as *mut u8, len);
        let _x: u32 = std::mem::transmute(0u32);
    }
}
