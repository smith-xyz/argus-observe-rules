use libloading::{Library, Symbol};

fn call_dynamic(path: &str, symbol: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let lib = Library::new(path)?;
    let func: Symbol<unsafe extern "C" fn()> = lib.get(symbol)?;
    unsafe { func() };
    Ok(())
}

fn indirect_call(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let lib = libloading::Library::new(path)?;
    let func = lib.get::<unsafe extern "C" fn()>(b"run")?;
    unsafe { func() };
    Ok(())
}
