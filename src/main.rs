use std::collections::HashMap;
use std::fs::{File, create_dir_all};
use std::io::Write;
use std::ops::Range;
use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand};
use indicatif::ProgressIterator;
use pelite::image::{
    IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_DEBUG,
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_TLS,
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, IMAGE_DLLCHARACTERISTICS_GUARD_CF,
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, IMAGE_DLLCHARACTERISTICS_NO_SEH,
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
};
use pelite::{FileMap, pe64};

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
    /// Print image info.
    Info {
        /// Path to the image you want to enable/disable ASLR for.
        #[arg(short, long)]
        image: PathBuf,
    },
    /// Set the ASLR bit on the specified image.
    SetAslr {
        /// Path to the image you want to enable/disable ASLR for.
        #[arg(short, long)]
        image: PathBuf,
        /// Whether the ASLR bit should be on or off.
        #[arg(action = ArgAction::Set, long, required = true)]
        enabled: bool,
        /// Path to write the modified image to, if this isn't specified it will do it in
        /// in-place.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
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
        Commands::Info { image } => {
            let map = FileMap::open(image)?;
            let pe = pe64::PeFile::from_bytes(&map)?;
            print_pe(&pe)?;
        }
        Commands::SetAslr {
            image,
            enabled,
            out,
        } => {
            let mut buffer = std::fs::read(image)?;
            patch_dynamic_base(&mut buffer, *enabled)?;

            let out = out.clone().unwrap_or(image.clone());
            std::fs::write(out, &buffer)?;

            println!("Patched DYNAMIC_BASE to {enabled}");
        }
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

            let modules = regions_by_modules(&modules, &regions);
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
                let Ok(memory) = read_region(process_handle, &region.range) else {
                    continue;
                };

                let filename = format!("{:x}-{:x}-UNK.dump", region.range.start, region.range.end,);

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

fn patch_dynamic_base(buffer: &mut [u8], enabled: bool) -> pelite::Result<()> {
    // Make sure we're operating on a valid PE image.
    let _ = pelite::PeFile::from_bytes(&*buffer)?;
    let (_dos, nt, _dirs, _sections) = unsafe { pe64::headers_mut(buffer) };

    if enabled {
        nt.OptionalHeader.DllCharacteristics |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    } else {
        nt.OptionalHeader.DllCharacteristics &= !IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    }

    Ok(())
}

/// Patch the PE header to make PointerToRawData point to the virtual start of the image.
fn patch_section_headers(buffer: &mut [u8]) -> pelite::Result<()> {
    let _ = pe64::PeFile::from_bytes(&*buffer)?;

    // Safety: pelite already validated `buffer` as a PE by PeFile::from_bytes.
    let (_dos, _nt, _dirs, sections) = unsafe { pe64::headers_mut(buffer) };

    for sh in sections.iter_mut() {
        sh.SizeOfRawData = sh.VirtualSize;
        sh.PointerToRawData = sh.VirtualAddress;
    }

    Ok(())
}

type ModuleRegionMap = HashMap<String, Vec<Range<isize>>>;

fn regions_by_modules(modules: &[ProcessModule], regions: &[MemoryRegion]) -> ModuleRegionMap {
    let mut by_mod: ModuleRegionMap = HashMap::new();

    for region in regions {
        let owner = modules
            .iter()
            .find(|m| region.range.start < m.range.end && region.range.end > m.range.start);

        if let Some(m) = owner {
            by_mod
                .entry(m.name.clone())
                .or_default()
                .push(region.range.clone());
        }
    }

    for ranges in by_mod.values_mut() {
        *ranges = merge_ranges(std::mem::take(ranges));
    }

    by_mod
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

fn print_pe<'a, P: pelite::pe::Pe<'a>>(pe: &P) -> Result<(), Box<dyn std::error::Error>> {
    fn dd_present(dd: &[IMAGE_DATA_DIRECTORY], idx: usize) -> bool {
        dd.get(idx)
            .map(|d| d.VirtualAddress != 0 && d.Size != 0)
            .unwrap_or(false)
    }

    fn has(flags: u16, flag: u16) -> bool {
        (flags & flag) != 0
    }

    let coff = pe.file_header();
    let opt = pe.optional_header();
    let dll = opt.DllCharacteristics;
    let dd = pe.data_directory();

    let ep_rva = opt.AddressOfEntryPoint as u64;
    let base = opt.ImageBase;
    let ep_va = base + ep_rva;

    let aslr = has(dll, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);
    let nx = has(dll, IMAGE_DLLCHARACTERISTICS_NX_COMPAT);
    let heva = has(dll, IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA);
    let cfg = has(dll, IMAGE_DLLCHARACTERISTICS_GUARD_CF);
    let no_seh = has(dll, IMAGE_DLLCHARACTERISTICS_NO_SEH);

    let relocs = dd_present(dd, IMAGE_DIRECTORY_ENTRY_BASERELOC);

    println!(
        "x64 sec={} ts=0x{:08x}",
        coff.NumberOfSections, coff.TimeDateStamp
    );
    println!(
        "base=0x{:x} ep=0x{:x} (va=0x{:x}) img=0x{:x}",
        base, ep_rva, ep_va, opt.SizeOfImage
    );
    println!(
        "aslr={} relocs={} nx={} heva={} cfg={} seh={}",
        aslr, relocs, nx, heva, cfg, !no_seh
    );
    println!(
        "dirs: imp={} exp={} tls={} dbg={}",
        dd_present(dd, IMAGE_DIRECTORY_ENTRY_IMPORT) as u8,
        dd_present(dd, IMAGE_DIRECTORY_ENTRY_EXPORT) as u8,
        dd_present(dd, IMAGE_DIRECTORY_ENTRY_TLS) as u8,
        dd_present(dd, IMAGE_DIRECTORY_ENTRY_DEBUG) as u8,
    );

    Ok(())
}
