use std::{collections::{HashMap, HashSet}, hash::{Hash, Hasher}};

use rWABIDB::instrumenter::Instrumenter;
use walrus::{ir::{BinaryOp, Call, ExtendedLoad, Instr, Load, LoadKind, MemArg, Store, StoreKind, Visitor, VisitorMut}, FunctionId, GlobalId, InstrLocId, InstrSeqBuilder, Local, LocalId, MemoryId, ValType};

pub struct MemTracer {
    pub trace_mem_id: MemoryId,
    pub trace_mem_pointer: GlobalId,
    // trace_mem_pointer_pre: GlobalId,
}

#[derive(Debug, Clone)]
pub struct StoreInstanceKind(pub Store);

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
pub struct LoadInstanceKind(pub Load);

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
pub struct MemInstrChecker {
    pub store_kinds: HashSet<StoreInstanceKind>,
    pub load_kinds: HashSet<LoadInstanceKind>,
}

impl<'instr> Visitor<'instr> for MemInstrChecker {
    fn visit_store(&mut self, instr: &Store) {
        self.store_kinds.insert(StoreInstanceKind(instr.clone()));
    }

    fn visit_load(&mut self, instr: &Load) {
        self.load_kinds.insert(LoadInstanceKind(instr.clone()));
    }
}

pub struct MemInstrHooker {
    pub store_hooks_map: HashMap<StoreInstanceKind, FunctionId>,
    pub load_hooks_map: HashMap<LoadInstanceKind, FunctionId>,
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

impl MemTracer {
    pub fn increment_mem_pointer(&self, seq: &mut InstrSeqBuilder, amount: u32) {
        seq
            .global_get(self.trace_mem_pointer)
            .i32_const(amount as i32)
            .binop(BinaryOp::I32Add)
            .global_set(self.trace_mem_pointer);
    }

    pub fn store_val_type(&self, seq: &mut InstrSeqBuilder, val_type: ValType, offset: u32) -> u32 {
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

    pub fn store(&self, seq: &mut InstrSeqBuilder, kind: StoreKind, offset: u32) -> u32 {
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

    pub fn trace_params(&self, seq: &mut InstrSeqBuilder, params: &[&Local], offset: &mut u32) {
        for l in params.into_iter() {
            self.trace_local(seq, l.id(), l.ty(), offset);
        }
    }

    pub fn trace_u32(&self, seq: &mut InstrSeqBuilder, code: u32, offset: &mut u32) {
        seq
            .global_get(self.trace_mem_pointer)
            .i32_const(code as i32);
        self.store_val_type(seq, ValType::I32, *offset);
        *offset += 4;
    }

    pub fn trace_local(&self, seq: &mut InstrSeqBuilder, id: LocalId, val_type: ValType, offset: &mut u32) {
        seq
            .global_get(self.trace_mem_pointer)
            .local_get(id);
        let amount = self.store_val_type(seq, val_type, *offset);
        *offset += amount;
    }
}

pub fn add_store_hooks(instrumenter: &mut Instrumenter, store_kinds: &HashSet<StoreInstanceKind>, mem_tracer: &MemTracer) -> HashMap<StoreInstanceKind, FunctionId> {
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

pub fn add_load_hooks(instrumenter: &mut Instrumenter, load_kinds: &HashSet<LoadInstanceKind>, mem_tracer: &MemTracer) -> HashMap<LoadInstanceKind, FunctionId> {
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