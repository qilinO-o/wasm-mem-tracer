use std::{collections::{HashMap, HashSet}, env, fmt, hash::{Hash, Hasher}};
use rWABIDB::instrumenter::{self, Instrumenter};
use walrus::{ir::{dfs_in_order, dfs_pre_order_mut, BinaryOp, Call, Instr, InstrLocId, MemArg, Store, StoreKind, Value, Visitor, VisitorMut}, FunctionId, GlobalId, InstrSeqBuilder, Local, MemoryId, ValType};
use wasmtime::{Config, Engine, Linker};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::WasiCtxBuilder;
use anyhow::Result;

struct MemTracer {
    trace_mem_id: MemoryId,
    trace_mem_pointer: GlobalId,
    trace_mem_pointer_pre: GlobalId,
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

#[derive(Default)]
struct StoreChecker {
    store_kinds: HashSet<StoreInstanceKind>,
}

impl<'instr> Visitor<'instr> for StoreChecker {
    // fn visit_instr(&mut self, instr: &'instr Instr, _: &'instr InstrLocId) {
    //     match instr {
    //         Instr::Store(store) => { 
    //             self.store_kinds.insert(StoreInstanceKind(store.clone()));
    //         },
    //         _ => { },
    //     }
    // }
    fn visit_store(&mut self, instr: &Store) {
        self.store_kinds.insert(StoreInstanceKind(instr.clone()));
    }
}

struct StoreHooker {
    store_hooks_map: HashMap<StoreInstanceKind, FunctionId>,
}

impl VisitorMut for StoreHooker {
    fn visit_instr_mut(&mut self, instr: &mut Instr, _: &mut InstrLocId) {
        match instr {
            Instr::Store(store) => { 
                *instr = Instr::Call(Call { 
                    func: *self.store_hooks_map.get(&StoreInstanceKind(store.clone())).unwrap() 
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

    let trace_mem_id = instrumenter.add_memory(false, 1, None);
    instrumenter.add_export(TRACE_MEMORY_EXPORT_NAME, trace_mem_id);
    let trace_mem_pointer = instrumenter.add_global(ValType::I32, true, Value::I32(TRACE_START_ADDR as i32));
    instrumenter.add_export(TRACE_MEM_POINTER_EXPORT_NAME, trace_mem_pointer);
    let trace_mem_pointer_pre = instrumenter.add_global(ValType::I32, true, Value::I32(TRACE_START_ADDR as i32));
    let mem_tracer = MemTracer {
        trace_mem_id,
        trace_mem_pointer,
        trace_mem_pointer_pre,
    };

    let mut store_checker = StoreChecker::default();
    instrumenter
        .iter_defined_functions()
        .for_each(|(_, f)| dfs_in_order(&mut store_checker, f, f.entry_block()));

    let mut store_hooker = StoreHooker {
        store_hooks_map: add_store_hooks(&mut instrumenter, &store_checker.store_kinds, &mem_tracer) 
    };

    instrumenter.for_scope_functions_mut(
        |_, f| dfs_pre_order_mut(&mut store_hooker, f, f.entry_block())
    );

    instrumenter.write_binary().unwrap();

    let wasm_binary = instrumenter.get_binary();

    let raw_trace = run_wasm_and_trace(&wasm_binary).expect("failed to run instrumented wasm and get trace");
    let records = match parse_trace(&raw_trace) {
        Ok(records) => records,
        Err(e) => {
            eprintln!("Parse error: {}", e);
            return;
        }
    };
    print_records(&records);
}

#[derive(Debug, Clone, PartialEq)]
pub enum RecordValue {
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    V128([u8; 16]),
}

impl fmt::Display for RecordValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordValue::I32(v) => write!(f, "I32({})", v),
            RecordValue::I64(v) => write!(f, "I64({})", v),
            RecordValue::F32(v) => write!(f, "F32({})", v),
            RecordValue::F64(v) => write!(f, "F64({})", v),
            RecordValue::V128(bytes) => {
                write!(f, "V128(")?;
                for (i, b) in bytes.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "0x{:02X}", b)?;
                }
                write!(f, ")")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TraceRecordStore {
    pub code: u32,
    pub addr: u32,
    pub value: RecordValue,
    pub offset: u32,
}

pub enum TraceRecord {
    StoreRecord(TraceRecordStore),
}

impl fmt::Display for TraceRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraceRecord::StoreRecord(r) => write!(
                f,
                "StoreRecord {{ code: 0x{:02X}, addr: {}, value: {}, offset: {} }}",
                r.code, r.addr, r.value, r.offset
            ),
        }
    }
}

pub fn print_records(records: &Vec<TraceRecord>) {
    let max_index = if records.is_empty() { 0 } else { records.len() - 1 };
    let width = std::cmp::max(1, max_index.to_string().len());

    for (i, record) in records.iter().enumerate() {
        println!("[{:>width$}] {}", i, record, width = width);
    }
}

#[derive(Debug)]
pub enum TraceParseError {
    UnexpectedEof { needed: usize, remaining: usize },
    InvalidData(String),
    TrailingBytes(usize),
}

impl std::error::Error for TraceParseError {}
impl fmt::Display for TraceParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraceParseError::UnexpectedEof { needed, remaining } => {
                write!(f, "unexpected EOF: need {} bytes but only {} remaining", needed, remaining)
            }
            TraceParseError::InvalidData(s) => write!(f, "invalid data: {}", s),
            TraceParseError::TrailingBytes(n) => write!(f, "trailing {} unread bytes after parsing", n),
        }
    }
}

struct BufferReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> BufferReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// try read n bytes and move pos
    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], TraceParseError> {
        if self.pos + n <= self.buf.len() {
            let s = &self.buf[self.pos..self.pos + n];
            self.pos += n;
            Ok(s)
        } else {
            Err(TraceParseError::UnexpectedEof {
                needed: n,
                remaining: self.buf.len().saturating_sub(self.pos),
            })
        }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn read_u32(&mut self) -> Result<u32, TraceParseError> {
        let s = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn read_i32(&mut self) -> Result<i32, TraceParseError> {
        let s = self.read_bytes(4)?;
        Ok(i32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn read_i64(&mut self) -> Result<i64, TraceParseError> {
        let s = self.read_bytes(8)?;
        Ok(i64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    fn read_f32(&mut self) -> Result<f32, TraceParseError> {
        let s = self.read_bytes(4)?;
        Ok(f32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn read_f64(&mut self) -> Result<f64, TraceParseError> {
        let s = self.read_bytes(8)?;
        Ok(f64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    fn read_v128(&mut self) -> Result<[u8; 16], TraceParseError> {
        let s = self.read_bytes(16)?;
        let mut a = [0u8; 16];
        a.copy_from_slice(s);
        Ok(a)
    }
}

fn parse_trace(raw_trace: &Vec<u8>) -> Result<Vec<TraceRecord>, TraceParseError> {
    let buf: &[u8] = raw_trace.as_slice();
    let mut reader = BufferReader::new(buf);
    let mut out: Vec<TraceRecord> = Vec::new();

    while reader.remaining() > 0 {
        let code = reader.read_u32()?;
        let addr = reader.read_u32()?;

        let value = match code {
            0x36 | 0x3A | 0x3B => {
                // i32 payload
                let v = reader.read_i32()?;
                RecordValue::I32(v)
            }
            0x37 | 0x3C | 0x3D | 0x3E => {
                // i64 payload
                let v = reader.read_i64()?;
                RecordValue::I64(v)
            }
            0x38 => {
                // f32 payload
                let v = reader.read_f32()?;
                RecordValue::F32(v)
            }
            0x39 => {
                // f64 payload
                let v = reader.read_f64()?;
                RecordValue::F64(v)
            }
            0xFD => {
                // v128 payload (16 bytes)
                let v = reader.read_v128()?;
                RecordValue::V128(v)
            }
            _ => {return Err(TraceParseError::InvalidData("Code mistached".to_string()));},
        };

        let offset = reader.read_u32()?;

        out.push(TraceRecord::StoreRecord(
            TraceRecordStore {
                code,
                addr,
                value,
                offset,
            })
        );
    }
    Ok(out)
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
            StoreKind::V128 => (0xFD, ValType::V128),
            StoreKind::I32_8 { .. } => (0x3A, ValType::I32),
            StoreKind::I32_16 { .. } => (0x3B, ValType::I32),
            StoreKind::I64_8 { .. } => (0x3C, ValType::I64),
            StoreKind::I64_16 { .. } => (0x3D, ValType::I64),
            StoreKind::I64_32 { .. } => (0x3E, ValType::I64),
        };
        // here is (addr: i32, value: any)
        // TODO: add instr_loc_id
        let args = &[ValType::I32, i_args];
        let func_id = instrumenter.add_function(Some(name), args, &[], &[], 
            |builder, locals| {
                let offset: &mut u32 = &mut 0;
                // record current mem_pointer
                builder
                    .global_get(mem_tracer.trace_mem_pointer)
                    .global_set(mem_tracer.trace_mem_pointer_pre);
                
                // trace code of the hooked instr
                mem_tracer.trace_u32(builder, opcode, offset);
                
                // trace params of the hooked instr
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

    // only api prefix is trace should be used outside
    fn trace_params(&self, seq: &mut InstrSeqBuilder, params: &[&Local], offset: &mut u32) {
        for l in params.into_iter() {
            seq
                .global_get(self.trace_mem_pointer)
                .local_get(l.id());
            let amount = self.store_val_type(seq, l.ty(), *offset);
            *offset += amount;
        }
    }

    fn trace_u32(&self, seq: &mut InstrSeqBuilder, code: u32, offset: &mut u32) {
        seq
            .global_get(self.trace_mem_pointer)
            .i32_const(code as i32);
        self.store_val_type(seq, ValType::I32, *offset);
        *offset += 4;
    }

}
