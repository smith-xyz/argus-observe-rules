use std::any::Any;

fn check_type(any: &dyn Any) -> bool {
    any.is::<String>()
}

fn assert_ref(any: &dyn Any) -> Option<&i32> {
    any.downcast_ref::<i32>()
}

fn assert_mut(any: &mut dyn Any) -> Option<&mut i32> {
    any.downcast_mut::<i32>()
}
