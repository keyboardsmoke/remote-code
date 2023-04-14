# remote-code

A rust library which empowers the user to invoke functions remotely without injecting an entire module to do it.

```rust
    // Example of usage
    #[allow(unused)]
    fn call_msgbox(msg: &str, title: &str) -> anyhow::Result<(), anyhow::Error>
    {
        let modname = "user32.dll\0";
        let procname = "MessageBoxW\0";
        let user32 = unsafe { GetModuleHandleA(modname.as_bytes().as_ptr() as *const i8) };
        if user32.is_null() {
            anyhow::bail!("GetModuleHandle(\"user32.dll\") returned nullptr.");
        }
        let addr = unsafe { GetProcAddress(user32, procname.as_bytes().as_ptr() as *const i8) };
        if addr.is_null() {
            anyhow::bail!("GetProcAddress(user32, \"MessageBoxA\") returned nullptr.");
        }
        let mut ctx = create_context(unsafe { GetCurrentProcess() })?;
        ctx.push_u8(0)?;
        ctx.push_wstring(msg.to_string())?;
        ctx.push_wstring(title.to_string())?;
        ctx.push_u32(MB_OKCANCEL)?;
        let mut ret = ctx.call_with_return(addr as u64)?;
        let buf = ctx.current_buffer()?;
        println!("Data: {:02X?}", buf);
        ctx.execute()?;
        let retval = ret.read()?;
        println!("ret: 0x{:X}", retval);
        println!("Leaks: {}", ctx.has_leaks());
        // Not required, Drop is implemented and this will be deallocated automatically
        // This is just for explicit deallocation
        println!("Is Return Deallocated first try: {}", ret.is_deallocated());
        ret.deallocate()?;
        println!("Is Return Deallocated second try: {}", ret.is_deallocated());
        Ok(())
    }
```