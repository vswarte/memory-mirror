use std::collections::HashMap;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::ops::Range;
use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand};
use indicatif::ProgressIterator;
use pelite::{pe32, pe64, Wrap};

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
            let regions = enumerate_regions(process_handle);

            let (modules, regions) = regions_by_modules(&modules, &regions);

            for (module_name, ranges) in modules.iter().progress() {
                for range in ranges {
                    let Ok(mut memory) = read_range(process_handle, range) else {
                        continue;
                    };

                    if *fixup_pe_headers {
                        patch_section_headers(memory.as_mut_slice())?;
                    }

                    let filename =
                        format!("{:x}-{:x}-{}.dump", range.start, range.end, module_name);

                    let mut file = File::create(output_dir.join(filename))?;
                    file.write_all(&memory)?;
                }
            }

            for region in regions.iter().progress() {
                let Ok(memory) = read_region(process_handle, region) else {
                    continue;
                };

                let filename = format!("{:x}-{:x}-UNK.dump", region.start, region.end,);

                let mut file = File::create(output_dir.join(filename))?;
                file.write_all(&memory)?;
            }

            if *suspend_threads {
                resume_threads(suspended_threads);
            }
        }
    }

    Ok(())
}

/// Patch the PE header to make PointerToRawData point to the virtual start of the exe.
fn patch_section_headers(buffer: &mut [u8]) -> pelite::Result<()> {
    let pe = pe64::PeFile::from_bytes(&*buffer)?;

    // Safety: pelite already validated `buffer` as a PE in the line above.
    let (_dos, _nt, _dirs, sections) = unsafe { pe64::headers_mut(buffer) };

    for sh in sections.iter_mut() {
        sh.SizeOfRawData = sh.VirtualSize;
        sh.PointerToRawData = sh.VirtualAddress;
    }

    Ok(())
}

type ModuleRegionMap = HashMap<String, Vec<Range<isize>>>;

fn regions_by_modules(
    modules: &[ProcessModule],
    regions: &[MemoryRegion],
) -> (ModuleRegionMap, Vec<Range<isize>>) {
    let mut by_mod: ModuleRegionMap = HashMap::new();
    let mut unknown = Vec::new();

    for region in regions {
        let owner = modules
            .iter()
            .find(|m| region.range.start < m.range.end && region.range.end > m.range.start);

        if let Some(m) = owner {
            by_mod
                .entry(m.name.clone())
                .or_default()
                .push(region.range.clone());
        } else {
            unknown.push(region.range.clone());
        }
    }

    for ranges in by_mod.values_mut() {
        *ranges = merge_ranges(std::mem::take(ranges));
    }
    unknown = merge_ranges(unknown);

    (by_mod, unknown)
}

fn merge_ranges(mut ranges: Vec<Range<isize>>) -> Vec<Range<isize>> {
    if ranges.is_empty() {
        return ranges;
    }

    ranges.sort_by_key(|r| r.start);

    let mut out = Vec::with_capacity(ranges.len());
    let mut cur = ranges[0].clone();

    for r in ranges.into_iter().skip(1) {
        if r.start <= cur.end {
            cur.end = cur.end.max(r.end);
        } else {
            out.push(cur);
            cur = r;
        }
    }

    out.push(cur);

    out
}
