use crate::args::{Args, DumpType};
use crate::windows::api::GetLastError;
use crate::windows::consts::MEM_FREE;
use clap::Parser;
use pe_util::PE;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::ops::{Range, Sub};
mod args;
mod process;
mod windows;

use crate::process::{
    enumerate_memory_regions, enumerate_modules, freeze_process, get_dumpable_processes,
    open_process, read_memory, resume_threads, snapshot_process, MemoryRegion, ProcessModule,
};

fn main() {
    let args = Args::parse();

    match args.command {
        DumpType::Name { name } => {
            let name = name.to_lowercase();
            let processes = get_dumpable_processes()
                .into_iter()
                .filter(|p| p.name.to_lowercase() == name);

            for process in processes {
                println!("Dumping process {}...", process);
                let output_dir = &format!("{}/{}", args.path, process.pid);
                fs::create_dir(&output_dir).expect("Could not create directory for process");

                unsafe {
                    dump(&output_dir, process.pid);
                }
            }
        }
        DumpType::Pid { pid } => {
            let process = get_dumpable_processes()
                .into_iter()
                .find(|p| p.pid == pid)
                .expect("Could not find a process with specified ID");

            println!("Dumping process {}...", process);

            unsafe {
                dump(&args.path, process.pid);
            }
        }
    }
}

unsafe fn dump(path: &str, pid: u32) {
    let snapshot = match snapshot_process(pid) {
        Ok(e) => e,
        Err(_) => {
            panic!("Last Error: {}", GetLastError());
        }
    };
    let frozen_threads = freeze_process(snapshot, pid);

    let process_handle = open_process(pid).unwrap();

    let modules = enumerate_modules(process_handle, snapshot);
    let regions = enumerate_memory_regions(process_handle);

    let readable_regions = regions
        .into_iter()
        .filter(|m| m.state != MEM_FREE)
        .filter(|m| {
            !modules
                .iter()
                .any(|module| module.range.contains(&m.range.end.sub(1)))
        })
        .collect::<Vec<MemoryRegion>>();

    for module in modules {
        dump_module(path, process_handle, &module)
    }

    for region in readable_regions.into_iter() {
        dump_raw_region(path, process_handle, region);
    }

    resume_threads(frozen_threads);
}

unsafe fn dump_module(path: &str, process: usize, module: &ProcessModule) {
    if let Some(buffer) = read_memory(process, &module.range) {
        let buffer = patch_section_headers(buffer);
        let filename = build_filename(module.name.as_str(), &module.range);
        dump_buffer(&format!("{}/{}", path, filename), buffer);
    }
}

unsafe fn dump_raw_region(path: &str, process: usize, region: MemoryRegion) {
    if let Some(buffer) = read_memory(process, &region.range) {
        let filename = build_filename("UNK", &region.range);
        dump_buffer(&format!("{}/{}", path, filename), buffer);
    }
}

fn build_filename(label: &str, range: &Range<usize>) -> String {
    format!(
        "{:x}-{:x}-{}.dump",
        range.start,
        range.end - range.start,
        label
    )
}

fn dump_buffer(path: &str, buffer: Vec<u8>) {
    let mut file = File::create(path).unwrap();
    file.write_all(buffer.as_slice()).unwrap();
}

unsafe fn patch_section_headers(mut buffer: Vec<u8>) -> Vec<u8> {
    let mut pe = match PE::from_slice(&buffer[..]) {
        Ok(p) => p,
        Err(_) => {
            println!(
                "[!] Could not validate PE. Patching header and assuming slice is a valid header."
            );
            buffer[0] = b'M';
            buffer[1] = b'Z';
            PE::from_slice_unchecked(&buffer[..])
        }
    };

    let sections = pe.section_headers_mut();
    for sections in sections {
        // Since we're dumping from memory we need to correct the PointerToRawData and SizeOfRawData
        // such that analysis tools can locate the sections again.
        sections.SizeOfRawData = sections.Misc.VirtualSize;
        sections.PointerToRawData = sections.VirtualAddress;
    }

    buffer
}
