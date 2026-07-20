use std::any::{Any, TypeId};

fn inspect_type<T: 'static>() -> TypeId {
    TypeId::of::<T>()
}

fn inspect_object(obj: &dyn Any) -> TypeId {
    obj.type_id()
}

fn type_layout<T>() -> (usize, usize) {
    (std::mem::size_of::<T>(), std::mem::align_of::<T>())
}

fn type_name<T>() -> &'static str {
    std::any::type_name::<T>()
}
