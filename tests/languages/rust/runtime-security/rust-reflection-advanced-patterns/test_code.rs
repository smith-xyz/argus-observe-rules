use std::any::Any;

fn load_generated() {
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}

fn load_str(path: &str) -> &'static str {
    include_str!(path)
}

fn downcast(obj: &dyn Any) -> Option<&String> {
    obj.downcast_ref::<String>().map(|s| s)
}

fn downcast_mut(obj: &mut dyn Any) -> Option<&mut String> {
    obj.downcast_mut::<String>()
}
