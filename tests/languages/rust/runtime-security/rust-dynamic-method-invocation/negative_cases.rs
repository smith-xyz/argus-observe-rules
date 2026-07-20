fn call_direct(obj: &dyn Runnable) {
    obj.run();
}

trait Runnable {
    fn run(&self);
}
