fn object_ptr<T>(obj: &T) -> *const T {
    obj as *const T
}
