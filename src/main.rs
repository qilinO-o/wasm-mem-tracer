mod trace_parser;
mod trace_analyzer;
mod mem_tracer;
use crate::trace_parser::{parse_trace, print_records};
use crate::trace_analyzer::analysis_trace;
use crate::mem_tracer::{add_load_hooks, add_store_hooks, MemInstrChecker, MemInstrHooker, MemTracer};

use std::env;
use rWABIDB::instrumenter::{self, Instrumenter};
use walrus::{ir::{dfs_in_order, dfs_pre_order_mut, Const, Instr, Value}, ValType};
use wasmtime::{Config, Engine, Linker};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::WasiCtxBuilder;
use anyhow::Result;

const TRACE_START_ADDR: usize = 0;
const TRACE_MEMORY_EXPORT_NAME: &str = "_trace_memory";
const TRACE_MEM_POINTER_EXPORT_NAME: &str = "_trace_mem_pointer";

fn main() {
    let args: Vec<String> = env::args().collect();
    let file_name_prefix = &args[1];
    let mut instrumenter = Instrumenter::from_config(
        instrumenter::InstrumentConfig::new(
            format!("./playground/{}.wasm", file_name_prefix),
            format!("./playground/{}_instrumented.wasm", file_name_prefix),
        )
    ).unwrap();

    // add aux memory and global for trace
    let trace_mem_id = instrumenter.add_memory(false, 1, None);
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

    // try execute the instrumented wasm with wasmtime to get raw trace in binary format
    let wasm_binary = instrumenter.get_binary();
    let raw_trace = run_wasm_and_trace(&wasm_binary).expect("failed to run instrumented wasm and get trace");
    
    // parse the raw trace
    let records = match parse_trace(&raw_trace) {
        Ok(records) => records,
        Err(e) => {
            eprintln!("Parse error: {}", e);
            return;
        }
    };
    print_records(&records);

    let defects = analysis_trace(&records);
    println!("{:?}", defects);
}

fn run_wasm_and_trace(wasm_binary: &Vec<u8>) -> Result<Vec<u8>> {
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