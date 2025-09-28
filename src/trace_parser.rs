use std::fmt;

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
    pub loc: u32,
    pub addr: u32,
    pub value: RecordValue,
    pub offset: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TraceRecordLoad {
    pub code: u32,
    pub loc: u32,
    pub addr: u32,
    pub value: RecordValue,
    pub offset: u32,
}

pub enum TraceRecord {
    StoreRecord(TraceRecordStore),
    LoadRecord(TraceRecordLoad),
}

impl fmt::Display for TraceRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraceRecord::StoreRecord(r) => write!(
                f,
                "StoreRecord {{ code: 0x{:02X}, loc: 0x{:X}, addr: {}, value: {}, offset: {} }}",
                r.code, r.loc, r.addr, r.value, r.offset
            ),
            TraceRecord::LoadRecord(r) => write!(
                f,
                " LoadRecord {{ code: 0x{:02X}, loc: 0x{:X}, addr: {}, value: {}, offset: {} }}",
                r.code, r.loc, r.addr, r.value, r.offset
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
#[allow(unused)]
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

pub fn parse_trace(raw_trace: &Vec<u8>) -> Result<Vec<TraceRecord>, TraceParseError> {
    let buf: &[u8] = raw_trace.as_slice();
    let mut reader = BufferReader::new(buf);
    let mut out: Vec<TraceRecord> = Vec::new();

    while reader.remaining() > 0 {
        let code = reader.read_u32()?;
        let addr = reader.read_u32()?;

        let value = match code {
            0x36 | 0x3A | 0x3B | // store
            0x28 | 0x2C | 0x2D | 0x2E | 0x2F => { // load
                // i32 payload
                let v = reader.read_i32()?;
                RecordValue::I32(v)
            }
            0x37 | 0x3C | 0x3D | 0x3E | // store
            0x29 | 0x30 | 0x31 | 0x32 | 0x33 | 0x34 | 0x35 => { // load
                // i64 payload
                let v = reader.read_i64()?;
                RecordValue::I64(v)
            }
            0x38 | // store
            0x2A => { // load
                // f32 payload
                let v = reader.read_f32()?;
                RecordValue::F32(v)
            }
            0x39 | // store
            0x2B => { // load
                // f64 payload
                let v = reader.read_f64()?;
                RecordValue::F64(v)
            }
            //FIXME:
            0xFD => {
                // v128 payload (16 bytes)
                let v = reader.read_v128()?;
                RecordValue::V128(v)
            }
            _ => {return Err(TraceParseError::InvalidData("Code mistached".to_string()));},
        };
        let loc = reader.read_u32()?;
        let offset = reader.read_u32()?;

        match code {
            0x36 | 0x3A | 0x3B | 0x37 | 0x3C | 0x3D | 0x3E | 0x38 | 0x39 => { // store
                out.push(TraceRecord::StoreRecord(
                    TraceRecordStore {
                        code,
                        loc,
                        addr,
                        value,
                        offset,
                    })
                );
            }
            0x28 | 0x2C | 0x2D | 0x2E | 0x2F | 0x29 | 0x30 | 0x31 | 0x32 | 0x33 | 0x34 | 0x35 | 0x2A | 0x2B => { // load
                out.push(TraceRecord::LoadRecord(
                    TraceRecordLoad {
                        code,
                        loc,
                        addr,
                        value,
                        offset,
                    })
                );
            }
            _ => {
                return Err(TraceParseError::InvalidData("Code mistached".to_string()));
            }
        }
    }
    Ok(out)
}