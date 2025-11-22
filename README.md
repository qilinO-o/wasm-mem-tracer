# wasm-mem-tracer

A CLI tool for tracing and analyzing memory access patterns in WebAssembly binaries through instrumentation. This tool identifies three types of memory performance defects: dead store, silent store, and silent read.

## Features

- **Binary Instrumentation**: Automatically instruments WebAssembly binaries to trace all memory operations
- **Memory Access Analysis**: Identifies performance bottlenecks in memory access patterns
- **Defect Detection**: Detects three types of memory performance issues:
  - **Dead Store**: A store operation that is overwritten before the stored value is ever read
  - **Silent Store**: A store operation that writes the same value that already exists in memory
  - **Silent Read**: A read operation that immediately follows a store of the same value (redundant load)
- **Detailed Reporting**: Provides multiple levels of output detail from summary to full trace

## Building

All done by cargo:

```bash
cargo build --release
```

## Usage

### Basic Command Line Interface

```bash
mem-tracer [OPTIONS] <INPUT_WASM> [-- <WASM_ARGS>...]
```

### Options

- `<INPUT_WASM>`: Input `.wasm` file (must end with `.wasm`)
- `-o, --out <OUTPUT_WASM>`: Set the output file name (default: `<input>_instrumented.wasm`)
- `-r, --run`: Execute the instrumented WebAssembly and analyze the trace
- `-f, --full`: Set verbosity level for output reporting:
  - `-f`: Show deduplicated memory defects hashed by wasm binary address
  - `-ff`: Show all memory defects records by index
  - `-fff`: Show full memory access trace
- `-- <WASM_ARGS>...`: Arguments forwarded to the wasmtime engine

### Examples

1. **Instrument a WebAssembly binary:**
   ```bash
   mem-tracer program.wasm
   # Creates: program_instrumented.wasm
   ```

2. **Instrument and run with analysis:**
   ```bash
   mem-tracer program.wasm --run
   ```

3. **Get detailed defect reports:**
   ```bash
   mem-tracer program.wasm --run -ff
   ```

4. **Full trace output (for debugging):**
   ```bash
   mem-tracer program.wasm --run -fff
   ```

5. **Pass arguments to the WebAssembly program:**
   ```bash
   mem-tracer program.wasm --run -f -- arg1 arg2
   ```

## Architecture

### Instrumentation Process

The tool uses the `rWABIDB` library to instrument WebAssembly binaries by:

1. **Memory Tracer Setup**: Adds auxiliary memory and global variables for trace recording
2. **Instruction Analysis**: Scans the binary to identify all load and store instruction types
3. **Hook Function Generation**: Creates specialized hook functions for each memory operation type
4. **Instrumentation Insertion**: Replaces original memory instructions with calls to hook functions
5. **Trace Recording**: Each hook records operation details (opcode, address, value, instruction location)

### Trace Analysis

The recorded trace is analyzed to detect performance defects:

- **Dead Store Detection**: Identifies stores that are overwritten before being read
- **Silent Store Detection**: Finds stores that write unchanged values to memory
- **Silent Read Detection**: Detects redundant loads after stores of the same value

### Output Format

The tool provides three levels of output detail:

#### Level 1 (`-f`): Deduplicated Defects
```
DedupDefects (by wasm binary addr) {
  dead_store_pairs (2 entries):
    (A1B2, C3D4)
    (E5F6, G7H8)
  silent_store_pairs (1 entries):
    (I9J0, K1L2)
  silent_load_pairs (0 entries):
}
```

#### Level 2 (`-ff`): All Defects by Index
```
DefectResults (by index) {
  dead_store_pairs (2 entries):
    (15, 42)
    (73, 128)
  silent_store_pairs (1 entries):
    (24, 89)
  silent_load_pairs (0 entries):
}
```

#### Level 3 (`-fff`): Full Trace
Complete memory access trace with all operations, addresses, and values.

## Technical Details

### Hook Function Generation

The tool generates custom hook functions for each type of memory instruction found in the binary. Each hook:

1. Records the instruction opcode
2. Captures instruction parameters (address, value, instruction location)
3. Records the memory offset of the operation
4. Updates the trace pointer
5. Executes the original memory instruction

### Trace Format

Each trace record contains:
- Instruction opcode (identifying the type of memory operation)
- Memory address
- Stored/loaded value
- Instruction location (binary address)
- Memory operation offset

### Memory Layout

The instrumentation adds:
- `_trace_memory`: Auxiliary memory for storing trace records
- `_trace_mem_pointer`: Global pointer to current trace position

## Dependencies

- `rWABIDB`: WebAssembly binary instrumentation framework
- `walrus`: WebAssembly parser and manipulation library
- `wasmtime`: WebAssembly runtime for execution
- `wasmtime-wasi`: WASI support for wasmtime
- `anyhow`: Error handling
- `clap`: Command line argument parsing

## Integration

This tool can be integrated into WebAssembly development workflows to:

1. **Performance Optimization**: Identify memory access patterns that may impact performance
2. **Debugging**: Understand memory behavior during program execution
3. **Code Quality**: Detect potential memory-related issues during development
4. **Benchmarking**: Analyze memory access patterns for optimization opportunities

## Example Output Analysis

When analyzing a WebAssembly binary, the tool might report:

```
DedupDefects (by wasm binary addr) {
  dead_store_pairs (3 entries):
    (1234, 5678)     // Store at 0x1234 overwritten before read at 0x5678
    (9ABC, DEF0)     // Another dead store pair
    (2468, 1357)     // Third dead store instance
  silent_store_pairs (2 entries):
    (AAAA, BBBB)     // Store writes same value as existing memory
    (CCCC, DDDD)     // Redundant store operation
  silent_load_pairs (1 entries):
    (EEEE, FFFF)     // Load immediately after store of same value
}
```

This information helps developers optimize memory access patterns and eliminate redundant operations.