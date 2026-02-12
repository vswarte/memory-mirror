use std::ffi::{c_void, CStr};
use std::ops::Range;
use sysinfo::System;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    Module32First, Module32Next, Thread32First, Thread32Next, MODULEENTRY32, THREADENTRY32,
};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_FREE, PAGE_GUARD, PAGE_NOACCESS,
};
use windows::Win32::System::Threading::{
    OpenThread, ResumeThread, SuspendThread, THREAD_ALL_ACCESS,
};

pub fn get_dumpable_processes() -> Vec<DumpableProcess> {
    let mut system = System::new();
    system.refresh_all();

    let mut processes = system
        .processes()
        .iter()
        .map(|x| DumpableProcess {
            pid: x.0.as_u32(),
            name: x.1.name().to_string_lossy().to_string(),
        })
        .collect::<Vec<DumpableProcess>>();

    processes.sort_by(|a, b| b.pid.partial_cmp(&a.pid).unwrap());

    processes
}

#[derive(Debug, Clone)]
pub struct DumpableProcess {
    pub pid: u32,
    pub name: String,
}

/// Enumerate all the modules in the remote process.
pub fn enumerate_modules(snapshot: HANDLE) -> windows::core::Result<Vec<ProcessModule>> {
    let mut current = MODULEENTRY32 {
        dwSize: size_of::<MODULEENTRY32>() as u32,
        ..Default::default()
    };

    unsafe { Module32First(snapshot, &mut current) }?;

    let mut results = vec![];
    loop {
        let module_name = unsafe { CStr::from_ptr(current.szModule.as_ptr()) }
            .to_str()
            .unwrap()
            .to_string();

        let base = current.modBaseAddr as isize;

        results.push(ProcessModule {
            name: module_name,
            range: Range {
                start: base,
                end: base + current.modBaseSize as isize,
            },
        });

        // Getting an error here indicates that we've hit the end of the modules.
        if unsafe { Module32Next(snapshot, &mut current) }.is_err() {
            break;
        }
    }

    Ok(results)
}

#[derive(Debug)]
pub struct ProcessModule {
    pub name: String,
    pub range: Range<isize>,
}

/// Enumerate all the non free regions in the remote process.
pub fn enumerate_regions(process: HANDLE) -> Vec<MemoryRegion> {
    let mut current_address = None as Option<*const c_void>;
    let mut current_entry = MEMORY_BASIC_INFORMATION::default();
    let mut results = vec![];

    loop {
        unsafe {
            VirtualQueryEx(
                process,
                current_address,
                &mut current_entry,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            );
        }

        let base_address = current_entry.BaseAddress as usize;
        let next_address = (base_address + current_entry.RegionSize) as *const c_void;

        if current_entry.State != MEM_FREE {
            results.push(MemoryRegion {
                range: Range {
                    start: current_entry.BaseAddress as isize,
                    end: current_entry.BaseAddress as isize + current_entry.RegionSize as isize,
                },
            });
        }

        // TODO: This will cause infinite loops when `current_address` gets back into a `None` state.
        if current_address.map(|a| a == next_address).unwrap_or(false) {
            break;
        }

        current_address = Some(next_address);
    }

    results
}

#[derive(Debug)]
pub struct MemoryRegion {
    pub range: Range<isize>,
}

/// Reads a regions memory from the target process.
pub fn read_region(process: HANDLE, range: &Range<isize>) -> windows::core::Result<Vec<u8>> {
    let size = (range.end - range.start) as usize;
    let buffer = vec![0_u8; size];
    let mut bytes_read = 0;

    unsafe {
        ReadProcessMemory(
            process,
            range.start as *const c_void,
            buffer.as_ptr() as *mut c_void,
            size,
            Some(&mut bytes_read),
        )
    }?;

    Ok(buffer)
}

/// Suspend a remote processes's threads and return a list of their handles for unsuspending.
pub fn suspend_threads(snapshot: HANDLE, process: u32) -> windows::core::Result<Vec<HANDLE>> {
    let mut thread = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    unsafe { Thread32First(snapshot, &mut thread) }?;

    let mut handles = vec![];
    loop {
        if thread.th32OwnerProcessID == process {
            let handle = unsafe { OpenThread(THREAD_ALL_ACCESS, false, thread.th32ThreadID) };

            if let Ok(handle) = handle {
                handles.push(handle);
                unsafe { SuspendThread(handle) };
            }
        }

        if unsafe { Thread32Next(snapshot, &mut thread) }.is_err() {
            break;
        }
    }

    Ok(handles)
}

pub fn resume_threads(threads: Vec<HANDLE>) {
    for thread in threads.iter() {
        unsafe { ResumeThread(*thread) };
    }
}

/// Reads a regions memory from the target process.
pub fn read_range(process: HANDLE, range: &Range<isize>) -> windows::core::Result<Vec<u8>> {
    let size = (range.end - range.start) as usize;
    let mut buffer = vec![0_u8; size];

    let mut addr = range.start as usize;
    while addr < range.end as usize {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        unsafe {
            VirtualQueryEx(
                process,
                Some(addr as *const c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
        }

        let region_base = mbi.BaseAddress as usize;
        let region_end = region_base.saturating_add(mbi.RegionSize);

        let read_start = addr.max(range.start as usize);
        let read_end = region_end.max(range.end as usize);

        let readble = mbi.State == MEM_COMMIT
            && (mbi.Protect.0 & PAGE_NOACCESS.0) == 0
            && (mbi.Protect.0 & PAGE_GUARD.0) == 0;

        if readble && read_end > read_start {
            let dst_off = read_start - (range.start as usize);
            let len = read_end - read_start;

            if let Ok(chunk) = read_region(
                process,
                &((read_start as isize)..(read_end as isize)),
            ) {
                buffer[dst_off..dst_off + len].copy_from_slice(&chunk[..len]);
            }
        }

        addr = read_end;
        // addr = read_end;
    }

    Ok(buffer)
}
