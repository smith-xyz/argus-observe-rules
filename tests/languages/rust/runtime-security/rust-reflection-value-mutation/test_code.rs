fn mutate_ptr<T>(target: &mut T, value: T) {
    unsafe {
        std::ptr::write(target, value);
    }
}

fn mutate_replace<T>(target: &mut T, value: T) -> T {
    std::mem::replace(target, value)
}

fn unsafe_block() {
    unsafe {
        let x = 1;
        let _ = x;
    }
}
