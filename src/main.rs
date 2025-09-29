mod trace_parser;
mod trace_analyzer;
use crate::trace_parser::{parse_trace, print_records};
use crate::trace_analyzer::analysis_trace;

use std::{collections::{HashMap, HashSet}, env, hash::{Hash, Hasher}};
use rWABIDB::instrumenter::{self, Instrumenter};
use walrus::{ir::{dfs_in_order, dfs_pre_order_mut, BinaryOp, Call, Const, ExtendedLoad, Instr, InstrLocId, Load, LoadKind, MemArg, Store, StoreKind, Value, Visitor, VisitorMut}, FunctionId, GlobalId, InstrSeqBuilder, Local, LocalId, MemoryId, ValType};
use wasmtime::{Config, Engine, Linker};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::WasiCtxBuilder;
use anyhow::Result;

struct MemTracer {
    trace_mem_id: MemoryId,
    trace_mem_pointer: GlobalId,
    // trace_mem_pointer_pre: GlobalId,
}

#[derive(Debug, Clone)]
struct StoreInstanceKind(Store);

impl PartialEq for StoreInstanceKind {
    fn eq(&self, other: &Self) -> bool {
        format!("{:?}", self.0) == format!("{:?}", other.0)
    }
}

impl Eq for StoreInstanceKind {}

impl Hash for StoreInstanceKind {
    fn hash<H: Hasher>(&self, state: &mut H) {
        format!("{:?}", self.0).hash(state);
    }
}

#[derive(Debug, Clone)]
struct LoadInstanceKind(Load);

impl PartialEq for LoadInstanceKind {
    fn eq(&self, other: &Self) -> bool {
        format!("{:?}", self.0) == format!("{:?}", other.0)
    }
}

impl Eq for LoadInstanceKind {}

impl Hash for LoadInstanceKind {
    fn hash<H: Hasher>(&self, state: &mut H) {
        format!("{:?}", self.0).hash(state);
    }
}

#[derive(Default)]
struct MemInstrChecker {
    store_kinds: HashSet<StoreInstanceKind>,
    load_kinds: HashSet<LoadInstanceKind>,
}

impl<'instr> Visitor<'instr> for MemInstrChecker {
    fn visit_store(&mut self, instr: &Store) {
        self.store_kinds.insert(StoreInstanceKind(instr.clone()));
    }

    fn visit_load(&mut self, instr: &Load) {
        self.load_kinds.insert(LoadInstanceKind(instr.clone()));
    }
}

struct MemInstrHooker {
    store_hooks_map: HashMap<StoreInstanceKind, FunctionId>,
    load_hooks_map: HashMap<LoadInstanceKind, FunctionId>,
}

impl VisitorMut for MemInstrHooker {
    fn visit_instr_mut(&mut self, instr: &mut Instr, _: &mut InstrLocId) {
        match instr {
            Instr::Store(store) => { 
                *instr = Instr::Call(Call { 
                    func: *self.store_hooks_map.get(&StoreInstanceKind(store.clone())).unwrap() 
                });
            },
            Instr::Load(load) => {
                *instr = Instr::Call(Call { 
                    func: *self.load_hooks_map.get(&LoadInstanceKind(load.clone())).unwrap()
                });
            },
            _ => { },
        }
    }
}

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
    // TODO: check and record types of load instructions
    let mut mem_instr_checker = MemInstrChecker::default();
    instrumenter
        .iter_defined_functions()
        .for_each(|(_, f)| dfs_in_order(&mut mem_instr_checker, f, f.entry_block()));

    // add all hook functions for all types of store instructions used
    let mut mem_instr_hooker = MemInstrHooker {
        store_hooks_map: add_store_hooks(&mut instrumenter, &mem_instr_checker.store_kinds, &mem_tracer),
        load_hooks_map: add_load_hooks(&mut instrumenter, &mem_instr_checker.load_kinds, &mem_tracer),
    };
    // TODO: add all hook functions for all types of load instructions used

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
    // TODO: modify all load instructions to their related hook functions
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

fn add_store_hooks(instrumenter: &mut Instrumenter, store_kinds: &HashSet<StoreInstanceKind>, mem_tracer: &MemTracer) -> HashMap<StoreInstanceKind, FunctionId> {
    let mut ret: HashMap<StoreInstanceKind, FunctionId> = HashMap::new();
    for kind in store_kinds {
        let name = format!("_hook_{:?}", kind.0);
        // get the type of the specific wasm instruction as the hook func's type
        let (opcode, i_args) = match kind.0.kind {
            StoreKind::I32 { .. } => (0x36, ValType::I32),
            StoreKind::I64 { .. } => (0x37, ValType::I64),
            StoreKind::F32 => (0x38, ValType::F32),
            StoreKind::F64 => (0x39, ValType::F64),
            StoreKind::V128 => todo!(),
            StoreKind::I32_8 { .. } => (0x3A, ValType::I32),
            StoreKind::I32_16 { .. } => (0x3B, ValType::I32),
            StoreKind::I64_8 { .. } => (0x3C, ValType::I64),
            StoreKind::I64_16 { .. } => (0x3D, ValType::I64),
            StoreKind::I64_32 { .. } => (0x3E, ValType::I64),
        };
        // here is (addr: i32, value: any, instr_loc: i32)
        let args = &[ValType::I32, i_args, ValType::I32];
        let func_id = instrumenter.add_function(Some(name), args, &[], &[], 
            |builder, locals| {
                let offset: &mut u32 = &mut 0;
                // record current mem_pointer, used for write trace to file in wasm
                // builder
                //     .global_get(mem_tracer.trace_mem_pointer)
                //     .global_set(mem_tracer.trace_mem_pointer_pre);
                
                // trace code of the hooked instr
                mem_tracer.trace_u32(builder, opcode, offset);
                
                // trace params of the hooked instr, and the instr_loc followed
                // in the order of [addr, value, instr_loc]
                mem_tracer.trace_params(builder, locals, offset);

                // trace offset of the store instr
                mem_tracer.trace_u32(builder, kind.0.arg.offset, offset);
                
                // increment mem_pointer
                mem_tracer.increment_mem_pointer(builder, *offset);
                
                // write trace_memory[trace_mem_pointer_pre, trace_mem_pointer] to file
                // TODO:
                
                // do the hooked instr
                builder
                    .local_get(locals[0].id())
                    .local_get(locals[1].id())
                    .instr(kind.0.clone());
            }
        );
        ret.insert(kind.clone(), func_id);
    }
    ret
}

fn add_load_hooks(instrumenter: &mut Instrumenter, load_kinds: &HashSet<LoadInstanceKind>, mem_tracer: &MemTracer) -> HashMap<LoadInstanceKind, FunctionId> {
    let mut ret: HashMap<LoadInstanceKind, FunctionId> = HashMap::new();
    fn extend_helper(kind: &ExtendedLoad) -> u32 {
        match kind {
            ExtendedLoad::SignExtend => 0,
            ExtendedLoad::ZeroExtend | ExtendedLoad::ZeroExtendAtomic => 1,
        }
    }
    for kind in load_kinds {
        let name = format!("_hook_{:?}", kind.0);
        let (opcode, i_args) = match kind.0.kind {
            LoadKind::I32 { .. } => (0x28, ValType::I32),
            LoadKind::I64 { .. } => (0x29, ValType::I64),
            LoadKind::F32 => (0x2A, ValType::F32),
            LoadKind::F64 => (0x2B, ValType::F64),
            LoadKind::V128 => todo!(),
            LoadKind::I32_8 { kind } => (0x2C + extend_helper(&kind), ValType::I32),
            LoadKind::I32_16 { kind } => (0x2E + extend_helper(&kind), ValType::I32),
            LoadKind::I64_8 { kind } => (0x30 + extend_helper(&kind), ValType::I64),
            LoadKind::I64_16 { kind } => (0x32 + extend_helper(&kind), ValType::I64),
            LoadKind::I64_32 { kind } => (0x34 + extend_helper(&kind), ValType::I64),
        };
        // here is (addr: i32, instr_loc: i32)
        let args = &[ValType::I32, ValType::I32];
        let func_id = instrumenter.add_function(Some(name), args, &[i_args], &[i_args], 
            |builder, locals| {
                let offset: &mut u32 = &mut 0;
                // record current mem_pointer, used for write trace to file in wasm
                // builder
                //     .global_get(mem_tracer.trace_mem_pointer)
                //     .global_set(mem_tracer.trace_mem_pointer_pre);
                
                // trace code of the hooked instr
                mem_tracer.trace_u32(builder, opcode, offset);
                
                // do the hooked instr
                builder
                    .local_get(locals[0].id())
                    .instr(kind.0.clone())
                    .local_tee(locals[2].id());

                // trace params of the hooked instr, and the instr_loc followed
                // in the order of [addr, value, instr_loc]
                mem_tracer.trace_params(builder, &[locals[0], locals[2], locals[1]], offset);

                // trace offset of the load instr
                mem_tracer.trace_u32(builder, kind.0.arg.offset, offset);
                
                // increment mem_pointer
                mem_tracer.increment_mem_pointer(builder, *offset);
                
                // write trace_memory[trace_mem_pointer_pre, trace_mem_pointer] to file
                // TODO:
            }
        );
        ret.insert(kind.clone(), func_id);
    }
    ret
}

impl MemTracer {
    fn increment_mem_pointer(&self, seq: &mut InstrSeqBuilder, amount: u32) {
        seq
            .global_get(self.trace_mem_pointer)
            .i32_const(amount as i32)
            .binop(BinaryOp::I32Add)
            .global_set(self.trace_mem_pointer);
    }

    fn store_val_type(&self, seq: &mut InstrSeqBuilder, val_type: ValType, offset: u32) -> u32 {
        let kind = match val_type {
            ValType::I32 => StoreKind::I32 { atomic: false },
            ValType::I64 => StoreKind::I64 { atomic: false },
            ValType::F32 => StoreKind::F32,
            ValType::F64 => StoreKind::F64,
            ValType::V128 => StoreKind::V128,
            ValType::Ref(_) => StoreKind::I32 { atomic: false },
        };
        self.store(seq, kind, offset)
    }

    fn store(&self, seq: &mut InstrSeqBuilder, kind: StoreKind, offset: u32) -> u32 {
        let align = kind.width();
        seq.store(
            self.trace_mem_id, 
            kind, 
            MemArg {
                align: align,
                offset,
            },
        );
        align
    }

    fn trace_params(&self, seq: &mut InstrSeqBuilder, params: &[&Local], offset: &mut u32) {
        for l in params.into_iter() {
            self.trace_local(seq, l.id(), l.ty(), offset);
        }
    }

    fn trace_u32(&self, seq: &mut InstrSeqBuilder, code: u32, offset: &mut u32) {
        seq
            .global_get(self.trace_mem_pointer)
            .i32_const(code as i32);
        self.store_val_type(seq, ValType::I32, *offset);
        *offset += 4;
    }

    fn trace_local(&self, seq: &mut InstrSeqBuilder, id: LocalId, val_type: ValType, offset: &mut u32) {
        seq
            .global_get(self.trace_mem_pointer)
            .local_get(id);
        let amount = self.store_val_type(seq, val_type, *offset);
        *offset += amount;
    }
}
