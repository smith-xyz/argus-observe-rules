fn type_name<T: std::any::Any>(obj: &T) -> &'static str {
    std::any::type_name::<T>()
}
