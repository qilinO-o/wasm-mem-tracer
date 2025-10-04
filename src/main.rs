mod trace_parser;
mod trace_analyzer;
mod mem_tracer;
use crate::trace_parser::{parse_trace, print_records};
use crate::trace_analyzer::analysis_trace;
use crate::mem_tracer::{add_load_hooks, add_store_hooks, MemInstrChecker, MemInstrHooker, MemTracer};

use std::path::{Path, PathBuf};
use rWABIDB::instrumenter::{self, Instrumenter};
use walrus::{ir::{dfs_in_order, dfs_pre_order_mut, Const, Instr, Value}, ValType};
use wasmtime::{Config, Engine, Linker};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::WasiCtxBuilder;
use anyhow::Result;
use clap::Parser;

const TRACE_START_ADDR: usize = 0;
const TRACE_MEMORY_EXPORT_NAME: &str = "_trace_memory";
const TRACE_MEM_POINTER_EXPORT_NAME: &str = "_trace_mem_pointer";

#[derive(Debug, Parser)]
#[command(name = "mem-tracer", version = "0.1", about = "Trace wasm linear memory usage")]
struct Cli {
    #[arg(value_parser = parse_wasm_path)]
    input: PathBuf,

    // optional output file name, or by default 'xxx_instrumented.wasm'
    #[arg(short = 'o', long = "out")]
    out: Option<PathBuf>,

    // a sign -r, indicating whether to run the instrumented wasm
    #[arg(short = 'r', long = "run")]
    r_flag: bool,

    // a sign -f, indicating whether to print the full trace
    #[arg(short = 'f', long = "full")]
    f_flag: bool,

    // colletc all trailing args after --
    #[arg(last = true)]
    rest: Vec<String>,
}

fn parse_wasm_path(s: &str) -> Result<PathBuf, String> {
    let p = PathBuf::from(s);
    match p.extension().and_then(|e| e.to_str()) {
        Some(ext) if ext.eq_ignore_ascii_case("wasm") => Ok(p),
        _ => Err(format!("input file must be end with '.wasm', getting: {}", s)),
    }
}

fn default_output_for(input: &Path) -> PathBuf {
    let stem = input.file_stem().and_then(|s| s.to_str()).unwrap_or("output");
    let mut out_name = String::with_capacity(stem.len() + 20);
    out_name.push_str(stem);
    out_name.push_str("_instrumented.wasm");
    if let Some(parent) = input.parent() {
        parent.join(out_name)
    } else {
        PathBuf::from(out_name)
    }
}

fn main() {
    // cli logics
    let cli = Cli::parse();
    let input_path = cli.input.clone();
    let out_path = match &cli.out {
        Some(p) => p.clone(),
        None => default_output_for(&cli.input),
    };

    let mut wasm_args: Vec<String> = Vec::new();
    for a in &cli.rest {
        wasm_args.push(String::from(a));
    }

    let mut instrumenter = Instrumenter::from_config(
        instrumenter::InstrumentConfig::new(
            input_path,
            out_path,
        )
    ).unwrap();

    // add aux memory and global for trace
    let trace_mem_id = instrumenter.add_memory(false, 30000, None);
    instrumenter.add_export(TRACE_MEMORY_EXPORT_NAME, trace_mem_id);
    let trace_mem_pointer = instrumenter.add_global(ValType::I32, true, Value::I32(TRACE_START_ADDR as i32));
    instrumenter.add_export(TRACE_MEM_POINTER_EXPORT_NAME, trace_mem_pointer);
    // let trace_mem_pointer_pre = instrumenter.add_global(ValType::I32, true, Value::I32(TRACE_START_ADDR as i32));
    let mem_tracer = MemTracer {
        trace_mem_id,
        trace_mem_pointer,
        // trace_mem_pointer_pre,
    };

    // check and record types of store instructions
    // check and record types of load instructions
    let mut mem_instr_checker = MemInstrChecker::default();
    instrumenter
        .iter_defined_functions()
        .for_each(|(_, f)| dfs_in_order(&mut mem_instr_checker, f, f.entry_block()));

    // add all hook functions for all types of store instructions used
    // add all hook functions for all types of load instructions used
    let mut mem_instr_hooker = MemInstrHooker {
        store_hooks_map: add_store_hooks(&mut instrumenter, &mem_instr_checker.store_kinds, &mem_tracer),
        load_hooks_map: add_load_hooks(&mut instrumenter, &mem_instr_checker.load_kinds, &mem_tracer),
    };

    // add instr_loc before every store and load instruction
    let match_store_and_load: instrumenter::InstrMatcher = Box::new(|i: &Instr| {
        matches!(
            i,
            Instr::Load(..) | 
            Instr::Store(..)
        )
    });

    let instrloc_modifier: instrumenter::FragmentModifier = Box::new(|(_, loc), pre, _| {
        if let Instr::Const(Const {ref mut value}) = pre[0] {
            if let Value::I32(ref mut n) = *value {
                *n = loc.data() as i32;
            }
        }
    });

    let op = instrumenter::InstrumentOperation {
        targets: match_store_and_load,
        pre_instructions: vec![
            Instr::Const(Const{value: Value::I32(0xFFFF_FFFFu32 as i32)}),
        ],
        post_instructions: vec![],
        modifier: Some(instrloc_modifier),
    };

    instrumenter.instrument(&vec![op]);

    // modify all store instructions to their related hook functions
    // modify all load instructions to their related hook functions
    instrumenter.for_scope_functions_mut(
        |_, f| dfs_pre_order_mut(&mut mem_instr_hooker, f, f.entry_block())
    );

    // write the instrumented wasm to file
    instrumenter.write_binary().unwrap();

    if !cli.r_flag {
        return;
    }
    // try execute the instrumented wasm with wasmtime to get raw trace in binary format
    let wasm_binary = instrumenter.get_binary();
    let raw_trace = run_wasm_and_trace(&wasm_binary, &wasm_args).expect("failed to run instrumented wasm and get trace");
    
    // parse the raw trace
    let records = match parse_trace(&raw_trace) {
        Ok(records) => records,
        Err(e) => {
            eprintln!("Parse error: {}", e);
            return;
        }
    };

    if cli.f_flag {
        print_records(&records);
    }

    let defects = analysis_trace(&records);
    println!("{:?}", defects);
}

fn run_wasm_and_trace(wasm_binary: &Vec<u8>, wasm_args: &Vec<String>) -> Result<Vec<u8>> {
    let mut config = Config::new();
    config.wasm_multi_memory(true);
    let engine = Engine::new(&config)?;
    let wasm_module = wasmtime::Module::from_binary(&engine, &wasm_binary)?;
    
    let mut linker: Linker<WasiP1Ctx> = Linker::new(&engine);
    p1::add_to_linker_sync(&mut linker, |t| t)?;
    let pre = linker.instantiate_pre(&wasm_module)?;
    let wasi_ctx = WasiCtxBuilder::new()
        .inherit_stdio()
        .inherit_env()
        .args(wasm_args)
        .build_p1();

    let mut store = wasmtime::Store::new(&engine, wasi_ctx);
    
    let instance = pre.instantiate(&mut store)?;

    let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
    start.call(&mut store, ())?;

    let trace_mem_pointer = instance
        .get_global(&mut store, TRACE_MEM_POINTER_EXPORT_NAME)
        .ok_or(anyhow::format_err!("failed to find `{}` export", TRACE_MEM_POINTER_EXPORT_NAME))?;

    let trace_memory = instance
        .get_memory(&mut store, TRACE_MEMORY_EXPORT_NAME)
        .ok_or(anyhow::format_err!("failed to find `{}` export", TRACE_MEMORY_EXPORT_NAME))?;
    
    let trace_size: usize = trace_mem_pointer.get(&mut store).i32().unwrap() as usize;
    let mut raw_trace = vec![0u8; trace_size];
    let err = trace_memory.read(store, TRACE_START_ADDR, &mut raw_trace[..]);
    if err.is_err() {
        eprintln!("failed to read from trace memory");
    }
    
    Ok(raw_trace)
}