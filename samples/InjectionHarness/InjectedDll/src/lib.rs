#![crate_type = "cdylib"]

#[link(name = "kernel32")]
extern "system" {
    fn ExitProcess(uExitCode: u32) -> !;
}

/// Export invoked by the injector via LoadLibrary remote thread.
/// Exits the host process harmlessly so the sandbox is not harmed.
#[no_mangle]
pub extern "system" fn Injected() {
    unsafe {
        ExitProcess(0);
    }
}
