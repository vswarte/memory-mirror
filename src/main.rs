use std::fs::{File, create_dir_all};
use std::io::Write;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use indicatif::ProgressIterator;
use pelite::{Wrap, pe32, pe64};

mod process;

use crate::process::*;

use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPMODULE, TH32CS_SNAPTHREAD,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// List any running processes that are available for dumping.
    List,
    /// List the modules of the provided process.
    ListModules {
        /// Process ID of the process to list modules for.
        #[arg(short, long)]
        pid: u32,
    },
    /// List the memory regions of the provided process.
    ListRegions {
        /// Process ID of the process to list regions for.
        #[arg(short, long)]
        pid: u32,
    },
    /// Dump a given process's memory regions to disk.
    DumpRegions {
        /// Process ID of the process to dump.
        #[arg(short, long)]
        pid: u32,
        /// Directory to write the output to.
        #[arg(short, long)]
        output_dir: PathBuf,
        /// Suspend all the threads before dumping.
        #[arg(short, long)]
        suspend_threads: bool,
        /// Correct the PE headers SizeOfRawData and PointerToRawData to point to the aligned start
        /// of the raw data. This makes it possible for Ghidra to find the entrypoint.
        #[arg(short, long)]
        fixup_pe_headers: bool,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match &args.command {
        Commands::List => {
            for process in get_dumpable_processes().iter() {
                println!("{}\t{}", process.pid, process.name)
            }
        }
        Commands::ListModules { pid } => {
            let processes = get_dumpable_processes();
            let Some(process) = processes.iter().find(|f| f.pid == *pid) else {
                panic!("Could not find process {pid}");
            };

            let snapshot = unsafe {
                CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE, process.pid)
            }?;

            for module in enumerate_modules(snapshot)?.iter() {
                println!(
                    "{:#X}..{:#X}\t{}",
                    module.range.start, module.range.end, module.name
                )
            }
        }
        Commands::ListRegions { pid } => {
            let processes = get_dumpable_processes();
            let Some(process) = processes.iter().find(|f| f.pid == *pid) else {
                panic!("Could not find process {pid}");
            };

            let process_handle = unsafe {
                OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                    false,
                    process.pid,
                )
            }?;

            for region in enumerate_regions(process_handle).iter() {
                println!("{:#X}..{:#X}", region.range.start, region.range.end)
            }
        }
        Commands::DumpRegions {
            pid,
            output_dir,
            suspend_threads,
            fixup_pe_headers,
        } => {
            create_dir_all(output_dir)?;

            let processes = get_dumpable_processes();
            let Some(process) = processes.iter().find(|f| f.pid == *pid) else {
                panic!("Could not find process {pid}");
            };

            let process_handle = (unsafe {
                OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                    false,
                    process.pid,
                )
            })
            .expect("Could not open remote process");

            let snapshot = unsafe {
                CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE, process.pid)
            }?;

            let mut suspended_threads = Vec::new();
            if *suspend_threads {
                suspended_threads = process::suspend_threads(snapshot, process.pid)?;
            }

            let modules = enumerate_modules(snapshot)?;
            for region in enumerate_regions(process_handle).into_iter().progress() {
                let Ok(mut memory) = read_region(process_handle, &region.range) else {
                    continue;
                };

                let module = modules
                    .iter()
                    .find(|m| m.range.contains(&region.range.start));

                let file_name = if let Some(module) = module {
                    format!(
                        "{:x}-{:x}-{}.dump",
                        region.range.start, region.range.end, module.name
                    )
                } else {
                    format!("{:x}-{:x}-UNK.dump", region.range.start, region.range.end)
                };

                if *fixup_pe_headers && module.is_some() {
                    patch_section_headers(memory.as_mut_slice())?;
                }

                let mut file = File::create(output_dir.join(file_name))?;
                file.write_all(memory.as_slice())?;
            }

            if *suspend_threads {
                resume_threads(suspended_threads);
            }
        }
    }

    Ok(())
}

/// Patch the PE header to make PointerToRawData point to the virtual start of the exe.
pub fn patch_section_headers(buffer: &mut [u8]) -> pelite::Result<()> {
    // Validate the PE header by passing it through from_bytes.
    let pe = pelite::PeFile::from_bytes(&*buffer)?;

    match pe {
        Wrap::T32(_) => {
            // Safety: pelite already validated `buffer` as a PE in the line above.
            let (_dos, _nt, _dirs, sections) = unsafe { pe32::headers_mut(buffer) };

            for sh in sections.iter_mut() {
                sh.SizeOfRawData = sh.VirtualSize;
                sh.PointerToRawData = sh.VirtualAddress;
            }
        }
        Wrap::T64(_) => {
            // Safety: pelite already validated `buffer` as a PE in the line above.
            let (_dos, _nt, _dirs, sections) = unsafe { pe64::headers_mut(buffer) };

            for sh in sections.iter_mut() {
                sh.SizeOfRawData = sh.VirtualSize;
                sh.PointerToRawData = sh.VirtualAddress;
            }
        }
    }

    Ok(())
}
