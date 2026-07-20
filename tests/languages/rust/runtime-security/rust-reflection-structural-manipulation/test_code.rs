fn mutate<T>(target: &mut T, value: T) -> T {
    std::mem::replace(target, value)
}

fn swap_values<T>(a: &mut T, b: &mut T) {
    std::mem::swap(a, b);
}

fn take_value<T: Default>(target: &mut T) -> T {
    std::mem::take(target)
}

fn leak_value<T>(value: T) {
    std::mem::forget(value);
}
