use winapi::{ctypes::c_void, shared::{ntdef::HANDLE, minwindef::{FALSE, LPVOID, DWORD}}, um::{memoryapi::{VirtualAllocEx, WriteProcessMemory, ReadProcessMemory}, winnt::{MEM_COMMIT, PAGE_EXECUTE_READWRITE}, processthreadsapi::CreateRemoteThread, minwinbase::SECURITY_ATTRIBUTES, synchapi::WaitForSingleObject, errhandlingapi::GetLastError}};

pub struct ReturnValue
{
    pub process: HANDLE,
    pub address: u64
}

impl ReturnValue
{
    pub fn read(&self) -> anyhow::Result<u64, anyhow::Error>
    {
        let buf: [u8; std::mem::size_of::<u64>()] = [0, 0, 0, 0, 0, 0, 0, 0];
        let mut read_size: usize = 0;
        unsafe {
            if ReadProcessMemory(self.process, self.address as *mut c_void, buf.as_ptr() as *mut c_void, std::mem::size_of::<u64>(), &mut read_size) == FALSE {
                anyhow::bail!("ReadProcessMemory failed. {}", GetLastError());
            }
        }

        let res = u64::from_le_bytes(buf);
        Ok(res)
    }
}

pub struct Context
{
    pub process: HANDLE,
    pub engine: keystone_engine::Keystone,
    pub buffer: Vec<u8>,
    pub argument_count: usize,
    pub allocations: Vec<*mut c_void>
}

impl Context
{
    pub fn append_asm(&mut self, asm: &str) -> anyhow::Result<(), anyhow::Error>
    {
        let mut res = self.engine.asm(asm.to_string(), 0)?;
        self.buffer.append(&mut res.bytes);
        Ok(())
    }

    pub fn push_u8(&mut self, value: u8) -> anyhow::Result<(), anyhow::Error>
    {
        match self.argument_count {
            0 => {
                self.append_asm(format!("mov cl, 0x{:X}", value).as_str())?;
            },
            1 => {
                self.append_asm(format!("mov dl, 0x{:X}", value).as_str())?;
            },
            2 => {
                self.append_asm(format!("mov r8b, 0x{:X}", value).as_str())?;
            },
            3 => {
                self.append_asm(format!("mov r9b, 0x{:X}", value).as_str())?;
            },
            _ => {
                self.append_asm(format!("push 0x{:X}", value).as_str())?;
            }
        }
        self.argument_count += 1;
        Ok(())
    }

    pub fn push_u16(&mut self, value: u16) -> anyhow::Result<(), anyhow::Error>
    {
        match self.argument_count {
            0 => {
                self.append_asm(format!("mov cx, 0x{:X}", value).as_str())?;
            },
            1 => {
                self.append_asm(format!("mov dx, 0x{:X}", value).as_str())?;
            },
            2 => {
                self.append_asm(format!("mov r8w, 0x{:X}", value).as_str())?;
            },
            3 => {
                self.append_asm(format!("mov r9w, 0x{:X}", value).as_str())?;
            },
            _ => {
                self.append_asm(format!("pushw 0x{:X}", value).as_str())?;
            }
        }
        self.argument_count += 1;
        Ok(())
    }

    pub fn push_u32(&mut self, value: u32) -> anyhow::Result<(), anyhow::Error>
    {
        match self.argument_count {
            0 => {
                self.append_asm(format!("mov ecx, 0x{:X}", value).as_str())?;
            },
            1 => {
                self.append_asm(format!("mov edx, 0x{:X}", value).as_str())?;
            },
            2 => {
                self.append_asm(format!("mov r8d, 0x{:X}", value).as_str())?;
            },
            3 => {
                self.append_asm(format!("mov r9d, 0x{:X}", value).as_str())?;
            },
            _ => {
                self.push_u64(value as u64)?;
            }
        }
        self.argument_count += 1;
        Ok(())
    }

    pub fn push_u64(&mut self, value: u64) -> anyhow::Result<(), anyhow::Error>
    {
        match self.argument_count {
            0 => {
                self.append_asm(format!("movabs rcx, 0x{:X}", value).as_str())?;
            },
            1 => {
                self.append_asm(format!("movabs rdx, 0x{:X}", value).as_str())?;
            },
            2 => {
                self.append_asm(format!("movabs r8, 0x{:X}", value).as_str())?;
            },
            3 => {
                self.append_asm(format!("movabs r9, 0x{:X}", value).as_str())?;
            },
            _ => {
                // rax is clobbered
                self.append_asm(format!("movabs rax, 0x{:X}; push rax", value).as_str())?;
            }
        }
        self.argument_count += 1;
        Ok(())
    }

    pub fn push_cstring(&mut self, value: String) -> anyhow::Result<(), anyhow::Error>
    {
        let data: Vec<u8> = value.bytes().collect();
        let ptr = unsafe { self.commit(data) }?;
        self.push_u64(ptr)
    }

    pub fn push_wstring(&mut self, value: String) -> anyhow::Result<(), anyhow::Error>
    {
        let enc = value.encode_utf16();
        let mut utf16: Vec<u16> = enc.collect();
        utf16.push(0);

        let mut v: Vec<u8> = Vec::new();
        for i in utf16 {
            v.append(&mut i.to_le_bytes().to_vec());
        }
        let ptr = unsafe { self.commit(v) }?;
        self.push_u64(ptr)?;
        Ok(())
    }

    pub fn call(&mut self, dest: u64) -> anyhow::Result<(), anyhow::Error>
    {
        self.append_asm(format!("movabs rax, 0x{:X}", dest).as_str())?;
        self.append_asm("call rax")?;
        Ok(())
    }

    pub fn call_with_return(&mut self, dest: u64) -> anyhow::Result<ReturnValue, anyhow::Error>
    {
        let ptr = unsafe { self.allocate(std::mem::size_of::<u64>()) }?;
        self.append_asm(format!("movabs rax, 0x{:X}", dest).as_str())?;
        self.append_asm("call rax")?;
        self.append_asm(format!("movabs ds:[0x{:X}], rax", ptr).as_str())?;
        self.call(dest)?;
        Ok(ReturnValue { process: self.process, address: ptr })
    }

    pub fn execute(&mut self) -> anyhow::Result<(), anyhow::Error>
    {
        self.append_asm("add rsp, 0x28")?;
        self.append_asm("ret")?;
        let mem = unsafe { self.commit(self.buffer.clone()) }?;
        unsafe { self.thread_execute(mem as *mut c_void) }?;
        Ok(())
    }

    pub fn current_buffer(&mut self) -> anyhow::Result<Vec<u8>, anyhow::Error>
    {
        let original_buffer = self.buffer.clone();
        self.append_asm("add rsp, 0x28")?;
        self.append_asm("ret")?;
        let buffer = self.buffer.clone();
        self.buffer = original_buffer;
        Ok(buffer)
    }

    unsafe fn allocate(&self, size: usize) -> anyhow::Result<u64, anyhow::Error>
    {
        let res = VirtualAllocEx(self.process, 0 as *mut c_void, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if res.is_null() {
            anyhow::bail!("VirtualAllocEx failed.");
        }
        Ok(res as u64)
    }

    unsafe fn commit(&mut self, data: Vec<u8>) -> anyhow::Result<u64, anyhow::Error>
    {
        let mem = self.allocate(data.len())?;
        if WriteProcessMemory(self.process, mem as *mut c_void, data.as_ptr() as *const c_void, data.len(), 0 as *mut usize) == FALSE {
            anyhow::bail!("WriteProcessMemory failed.");
        }
        Ok(mem)
    }

    unsafe fn thread_execute(&self, ptr: *mut c_void) -> anyhow::Result<(), anyhow::Error>
    {
        let start_address = std::mem::transmute::<*mut c_void, unsafe extern "system" fn (LPVOID) -> DWORD>(ptr);
        let handle = CreateRemoteThread(self.process, 0 as *mut SECURITY_ATTRIBUTES, 0, Some(start_address), 0 as *mut c_void, 0, 0 as *mut u32);
        if handle.is_null() {
            anyhow::bail!("CreateRemoteThread failed.");
        }
        WaitForSingleObject(handle, winapi::um::winbase::INFINITE);
        Ok(())
    }
}

pub fn create_context(process: HANDLE) -> anyhow::Result<Context, anyhow::Error>
{
    let ks = keystone_engine::Keystone::new(keystone_engine::Arch::X86, keystone_engine::Mode::MODE_64);
    if ks.is_err() {
        return Err(anyhow::Error::msg("Unable to create keystone instance."));
    }
    let mut res = Context { process: process, engine: ks.unwrap(), buffer: Vec::new(), allocations: Vec::new(), argument_count: 0 };
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
        ctx.push_u64(u64::max_value() / 2)?;
        ctx.push_u32(u32::max_value())?;
        ctx.push_u8(u8::max_value())?;
        ctx.push_u16(18377)?;
        ctx.push_u32(377128993)?;
        ctx.call(0x1000)?;
        let res = ctx.current_buffer()?;
        Ok(res)
    }

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
        let ret = ctx.call_with_return(addr as u64)?;
        let buf = ctx.current_buffer()?;
        println!("Data: {:02X?}", buf);
        ctx.execute()?;
        let retval = ret.read()?;
        println!("ret: 0x{:X}", retval);
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
}