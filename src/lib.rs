use winapi::{ctypes::c_void, shared::{ntdef::HANDLE, minwindef::{LPVOID, DWORD}}, um::{processthreadsapi::CreateRemoteThread, minwinbase::SECURITY_ATTRIBUTES, synchapi::WaitForSingleObject}};

pub trait AsmSerializer
{
    fn make_asm_push(&self, index: usize) -> (u32, String);
}

impl AsmSerializer for u8
{
    fn make_asm_push(&self, index: usize) -> (u32, String)
    {
        match index {
            0 => {
                (0, format!("mov cl, 0x{:X}", *self))
            },
            1 => {
                (0, format!("mov dl, 0x{:X}", *self))
            },
            2 => {
                (0, format!("mov r8b, 0x{:X}", *self))
            },
            3 => {
                (0, format!("mov r9b, 0x{:X}", *self))
            },
            _ => {
                (0, format!("push 0x{:X}", *self))
            }
        }
    }
}

impl AsmSerializer for i8
{
    fn make_asm_push(&self, index: usize) -> (u32, String)
    {
        (*self as u8).make_asm_push(index)
    }
}

impl AsmSerializer for u16
{
    fn make_asm_push(&self, index: usize) -> (u32, String)
    {
        match index {
            0 => {
                (0, format!("mov cx, 0x{:X}", *self))
            },
            1 => {
                (0, format!("mov dx, 0x{:X}", *self))
            },
            2 => {
                (0, format!("mov r8w, 0x{:X}", *self))
            },
            3 => {
                (0, format!("mov r9w, 0x{:X}", *self))
            },
            _ => {
                (0, format!("pushw 0x{:X}", *self))
            }
        }
    }
}

impl AsmSerializer for i16
{
    fn make_asm_push(&self, index: usize) -> (u32, String)
    {
        (*self as u16).make_asm_push(index)
    }
}

impl AsmSerializer for u32
{
    fn make_asm_push(&self, index: usize) -> (u32, String)
    {
        match index {
            0 => {
                (0, format!("mov ecx, 0x{:X}", *self))
            },
            1 => {
                (0, format!("mov edx, 0x{:X}", *self))
            },
            2 => {
                (0, format!("mov r8d, 0x{:X}", *self))
            },
            3 => {
                (0, format!("mov r9d, 0x{:X}", *self))
            },
            _ => {
                (*self as u64).make_asm_push(index)
            }
        }
    }
}

impl AsmSerializer for i32
{
    fn make_asm_push(&self, index: usize) -> (u32, String)
    {
        (*self as u32).make_asm_push(index)
    }
}

impl AsmSerializer for u64
{
    fn make_asm_push(&self, index: usize) -> (u32, String)
    {
        match index {
            0 => {
                (0, format!("movabs rcx, 0x{:X}", *self))
            },
            1 => {
                (0, format!("movabs rdx, 0x{:X}", *self))
            },
            2 => {
                (0, format!("movabs r8, 0x{:X}", *self))
            },
            3 => {
                (0, format!("movabs r9, 0x{:X}", *self))
            },
            _ => {
                (0, format!("movabs rax, 0x{:X}; push rax", *self))
            }
        }
    }
}

impl AsmSerializer for i64
{
    fn make_asm_push(&self, index: usize) -> (u32, String)
    {
        (*self as u64).make_asm_push(index)
    }
}

impl AsmSerializer for f64
{
    fn make_asm_push(&self, index: usize) -> (u32, String)
    {
        match index {
            0 => {
                (0, format!("movabs rax, 0x{:X}; movq xmm0, rax", *self as u64))
            },
            1 => {
                (0, format!("movabs rax, 0x{:X}; movq xmm1, rax", *self as u64))
            },
            2 => {
                (0, format!("movabs rax, 0x{:X}; movq xmm2, rax", *self as u64))
            },
            3 => {
                (0, format!("movabs rax, 0x{:X}; movq xmm3, rax", *self as u64))
            },
            _ => {
                (0x10, format!("movabs rax, 0x{:X}; movq xmm4, rax; sub rsp, 0x10; movdqu [rsp], xmm4", *self as u64))
            }
        }
    }
}

pub struct ReturnValue
{
    process: Box<remote_utils::Process>,
    address: u64
}

impl ReturnValue
{
    pub fn read(&self) -> anyhow::Result<u64, anyhow::Error>
    {
        let value = self.process.read_memory(self.address, std::mem::size_of::<u64>())?;
        let raw_mem = value.into_boxed_slice();
        let box_mem = unsafe { Box::from_raw(Box::into_raw(raw_mem) as *mut [u8; 8]) };
        let unbox = *box_mem;
        let res = u64::from_le_bytes(unbox);
        Ok(res)
    }

    pub fn deallocate(&mut self) -> anyhow::Result<(), anyhow::Error>
    {
        let ptr = remote_utils::Pointer::from(self.address as *mut u8);
        self.process.deallocate(ptr)
    }

    pub fn is_deallocated(&self) -> bool
    {
        self.address == 0
    }
}

impl AsmSerializer for ReturnValue
{
    fn make_asm_push(&self, index: usize) -> (u32, String)
    {
        if self.is_deallocated() {
            panic!("Attempt to reference a deallocated return value.");
        }
        self.address.make_asm_push(index)
    }
}

impl Drop for ReturnValue
{
    fn drop(&mut self)
    {
        // Because we let the user optionally free this value themselves, we check first.
        // We also make a copy because deallocate if it succeeds will zero it.
        let addr = self.address;
        if addr != 0 {
            let res = self.deallocate();
            if res.is_err() {
                println!("Warning: Failed to deallocate ReturnValue at address 0x{:X}", addr);
            } else {
                println!("Deallocated ReturnValue memory at address 0x{:X}", addr);
            }
        }
    }
}

pub struct Context
{
    process: remote_utils::Process,
    engine: keystone_engine::Keystone,
    buffer: Vec<u8>,
    argument_count: usize,
    allocations: Vec<u64>,
    rsp_adjust: u64,
}

impl Context
{
    pub fn append_asm(&mut self, asm: &str) -> anyhow::Result<&mut Context, anyhow::Error>
    {
        let mut res = self.engine.asm(asm.to_string(), 0)?;
        self.buffer.append(&mut res.bytes);
        Ok(self)
    }

    // Will allocate and commit the vec to the remote memory, and push the address to it on the stack
    pub fn push_vec_address(&mut self, value: Vec<u8>) -> anyhow::Result<&mut Context, anyhow::Error>
    {
        let res = unsafe { self.commit_internal(value, true) }?;
        self.push(res)
    }

    pub fn push_array_address<const COUNT: usize>(&mut self, value: &[u8; COUNT]) -> anyhow::Result<&mut Context, anyhow::Error>
    {
        self.push_vec_address(value.to_vec())
    }

    pub fn push(&mut self, value: impl AsmSerializer) -> anyhow::Result<&mut Context, anyhow::Error>
    {
        let (rsp_adjust, asm) = value.make_asm_push(self.argument_count);
        self.append_asm(asm.as_str())?;
        if rsp_adjust > 0 {
            self.rsp_adjust += rsp_adjust as u64;
        }
        self.argument_count += 1;
        Ok(self)
    }

    pub fn push_cstring(&mut self, value: String) -> anyhow::Result<&mut Context, anyhow::Error>
    {
        let mut data: Vec<u8> = value.bytes().collect();
        data.push(0); // make sure it's null terminated.
        self.push_vec_address(data)
    }

    pub fn push_wstring(&mut self, value: String) -> anyhow::Result<&mut Context, anyhow::Error>
    {
        let enc = value.encode_utf16();
        let mut utf16: Vec<u16> = enc.collect();
        utf16.push(0);

        let mut v: Vec<u8> = Vec::new();
        for i in utf16 {
            v.append(&mut i.to_le_bytes().to_vec());
        }
        v.append(&mut vec![0x00, 0x00]); // make sure it's null terminated
        self.push_vec_address(v)
    }

    pub fn call(&mut self, dest: u64) -> anyhow::Result<&mut Context, anyhow::Error>
    {
        self.append_asm(format!("movabs rax, 0x{:X}", dest).as_str())?;
        self.append_asm("call rax")?;
        Ok(self)
    }

    pub fn call_with_return(&mut self, dest: u64) -> anyhow::Result<ReturnValue, anyhow::Error>
    {
        // don't track this entry, we don't want it to be cleared when we execute.
        // So, the best move here is to allow freeing it in the ReturnValue...
        let ptr = unsafe { self.allocate_internal(std::mem::size_of::<u64>(), false) }?;
        self.append_asm(format!("movabs rax, 0x{:X}", dest).as_str())?;
        self.append_asm("call rax")?;
        self.append_asm(format!("movabs ds:[0x{:X}], rax", ptr).as_str())?;
        self.call(dest)?;
        Ok(ReturnValue { process: Box::new(remote_utils::Process { handle: remote_utils::Handle { handle: self.process.handle().generic() } }), address: ptr })
    }

    pub fn execute(&mut self) -> anyhow::Result<&mut Context, anyhow::Error>
    {
        // any rsp adjusting we did to push sse registers gets fixed here
        // we start with 0x28 of stack, so we adjust more to compensate
        let rsp_adjust_amount = 0x28 + self.rsp_adjust;
        self.append_asm(format!("add rsp, 0x{:02X}", rsp_adjust_amount).as_str())?;
        self.append_asm("ret")?;
        let mem = unsafe { self.commit_internal(self.buffer.clone(), true) }?;
        unsafe { self.thread_execute(mem as *mut c_void) }?;
        self.buffer.clear();
        self.allocations.retain(|x| {
            let dec = self.process.deallocate(remote_utils::Pointer::from(*x as *mut c_void));
            if dec.is_err() {
                println!("Warning: Failed to deallocate memory at 0x{:X}", *x);
                return true;
            }
            false
        });
        self.argument_count = 0;

        // rsp adjust is for the entire thread, so we keep it
        // self.rsp_adjust = 0;

        // We still return self here because you can actually chain more pushes, calls and executions
        // The only thing you can't really chain is call_with_return, because you need the return value
        Ok(self)
    }

    pub fn has_leaks(&self) -> bool
    {
        !self.allocations.is_empty()
    }

    pub fn current_buffer(&mut self) -> anyhow::Result<Vec<u8>, anyhow::Error>
    {
        let original_buffer = self.buffer.clone();
        let rsp_adjust_amount = 0x28 + self.rsp_adjust;
        self.append_asm(format!("add rsp, 0x{:02X}", rsp_adjust_amount).as_str())?;
        self.append_asm("ret")?;
        let buffer = self.buffer.clone();
        self.buffer = original_buffer;
        Ok(buffer)
    }

    pub fn allocate(&mut self, size: usize) -> anyhow::Result<u64, anyhow::Error>
    {
        unsafe { self.allocate_internal(size, true) }
    }

    pub fn commit(&mut self, data: Vec<u8>) -> anyhow::Result<u64, anyhow::Error>
    {
        unsafe { self.commit_internal(data, true) }
    }

    unsafe fn allocate_internal(&mut self, size: usize, track: bool) -> anyhow::Result<u64, anyhow::Error>
    {
        let res = self.process.allocate(size);
        if res.is_err() {
            anyhow::bail!("remote allocate failed.");
        }
        let addr = res.ok().unwrap().u64();
        if track { 
            self.allocations.push(addr);
        }
        Ok(addr)
    }

    unsafe fn commit_internal(&mut self, data: Vec<u8>, track: bool) -> anyhow::Result<u64, anyhow::Error>
    {
        let mem = self.allocate_internal(data.len(), track)?;
        self.process.write_memory(mem, &data)?;
        Ok(mem)
    }

    unsafe fn thread_execute(&self, ptr: *mut c_void) -> anyhow::Result<(), anyhow::Error>
    {
        let start_address = std::mem::transmute::<*mut c_void, unsafe extern "system" fn (LPVOID) -> DWORD>(ptr);
        let handle = CreateRemoteThread(self.process.handle().generic() as *mut c_void, std::ptr::null_mut::<SECURITY_ATTRIBUTES>(), 0, Some(start_address), std::ptr::null_mut::<c_void>(), 0, std::ptr::null_mut::<u32>());
        if handle.is_null() {
            anyhow::bail!("CreateRemoteThread failed.");
        }
        WaitForSingleObject(handle, winapi::um::winbase::INFINITE);
        Ok(())
    }
}

impl Drop for Context
{
    fn drop(&mut self)
    {
        if !self.allocations.is_empty() {
            self.allocations.retain(|x| {
                let res = self.process.deallocate(remote_utils::Pointer::from(*x as *mut c_void));
                if res.is_err() {
                    println!("Warning: Failed to deallocate memory at 0x{:X}", *x);
                    return true;
                }
                false
            });
        }
    }
}

pub fn create_context(process: HANDLE) -> anyhow::Result<Context, anyhow::Error>
{
    let ks = keystone_engine::Keystone::new(keystone_engine::Arch::X86, keystone_engine::Mode::MODE_64);
    if ks.is_err() {
        return Err(anyhow::Error::msg("Unable to create keystone instance."));
    }
    let h = remote_utils::Handle { handle: process as u64 };
    let mut res = Context { process: remote_utils::Process { handle: h }, engine: ks.unwrap(), buffer: Vec::new(), allocations: Vec::new(), argument_count: 0, rsp_adjust: 0 };
    res.append_asm("sub rsp, 0x28")?;
    Ok(res)
}

#[cfg(test)]
mod tests
{
    use winapi::um::{processthreadsapi::GetCurrentProcess, libloaderapi::{GetProcAddress, GetModuleHandleA}, winuser::MB_OKCANCEL};

    use super::*;

    fn run_test() -> anyhow::Result<Vec<u8>, anyhow::Error>
    {
        let mut ctx = create_context(unsafe { GetCurrentProcess() })?;
        let res = ctx.push((u64::max_value() / 2) as u64)?.push(u32::max_value())?.push(u8::max_value())?.push(18377 as u16)?.push(377128993 as u32)?.call(0x1000)?.current_buffer()?;
        Ok(res)
    }

    // Example of usage
    #[cfg(target_os = "windows")]
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
        let mut ret = ctx.push(0)?.push_wstring(msg.to_string())?.push_wstring(title.to_string())?.push(MB_OKCANCEL)?.call_with_return(addr as u64)?;
        let buf = ctx.current_buffer()?;
        println!("Data: {:02X?}", buf);
        ctx.execute()?;
        let retval = ret.read()?;
        println!("ret: 0x{:X}", retval);
        println!("Leaks: {}", ctx.has_leaks());
        println!("Is Return Deallocated first try: {}", ret.is_deallocated());
        ret.deallocate()?;
        println!("Is Return Deallocated second try: {}", ret.is_deallocated());
        Ok(())
    }

    #[test]
    fn test()
    {
        let expected_result: Vec<u8> = vec![
            0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28
            0x48, 0xB9, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, // movabs rcx, 0x7fffffffffffffff
            0xBA, 0xFF, 0xFF, 0xFF, 0xFF,  // mov edx, 0xffffffff
            0x41, 0xB0, 0xFF, // mov r8b, 0xff
            0x66, 0x41, 0xB9, 0xC9, 0x47, // mov r9w, 0x47c9
            0x48, 0xB8, 0x21, 0x88, 0x7A, 0x16, 0x00, 0x00, 0x00, 0x00, // movabs rax, 0x167a8821
            0x50, // push rax
            0x48, 0xB8, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, 0x1000 
            0xFF, 0xD0, // call rax
            0x48, 0x83, 0xC4, 0x28, // add rsp, 0x28 
            0xC3 // ret
        ];

        let p = run_test();
        assert_ne!(p.is_err(), true);
        assert_eq!(expected_result, p.unwrap());
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn pop_msgbox()
    {
        let res = call_msgbox("Hello, World!", "Hey!");
        if res.is_err() {
            let err = res.err().unwrap();
            println!("Backtrace for {}: {}", err.to_string(), err.backtrace());
        } else {
            assert_eq!(res.is_ok(), true);
        }
    }
}