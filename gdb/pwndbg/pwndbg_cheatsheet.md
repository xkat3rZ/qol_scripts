## Starting and Configuration

Standard GDB commands work, but `pwndbg` adds automatic context and security checks.

1. `checksec`
    
    1. Print binary security mitigations (RELRO, Canary, NX, PIE, RPATH).
        
2. `piebase`
    
    1. Calculate and print the base address of the PIE (Position Independent Executable) binary.
        
3. `vmmap`
    
    1. Display the virtual memory mapping (replaces `info proc mappings` with a color-coded, easier-to-read table).
        
4. `entry`
    
    1. Run execution until the entry point of the program (useful for libraries or PIE binaries).
        
5. `start`
    
    1. Short for `break main` and `run`. Stops at the first instruction of `main`.
        

## Context and Interface

`pwndbg` automatically displays a "context" dashboard (Regs, Disasm, Stack, Backtrace) at every stop.

1. `context`
    
    1. Reprint the full dashboard (useful if you cleared the screen).
        
2. `context sections <regs/code/stack/args/ghidra>`
    
    1. Configure which sections appear in the context display.
        
3. `regs`
    
    1. Print all registers in a readable format.
        
4. `nearpc`
    
    1. Print the disassembly around the current Program Counter (PC).
        

## Execution Control

`pwndbg` adds commands to skip over loops or jump directly to relevant instructions.

1. `nextcall` (or `nc`)
    
    1. Execute until the next `call` instruction.
        
2. `nextjmp` (or `nj`)
    
    1. Execute until the next `jump` instruction.
        
3. `nextret`
    
    1. Execute until the next `ret` instruction (useful to skip to end of function).
        
4. `stepuntilasm <inst>`
    
    1. Step until a specific assembly instruction (e.g., `stepuntilasm cmp`).
        
5. `finish`
    
    1. (Standard GDB) Run until the current function returns.
        

## Inspection and Memory (`telescope` vs `x`)

The `telescope` command is the most powerful memory inspection tool in `pwndbg`, resolving pointers recursively.

1. `telescope <addr> <count>` (or `tel`)
    
    1. Print memory at `<addr>` and recursively resolve pointers to strings, code, or other pointers.
        
    2. Example: `tel $sp 20` (Show 20 lines of the stack, resolving values).
        
2. `stack <count>`
    
    1. Shortcut for `telescope $sp`. Shows the current stack frame.
        
3. `hexdump <addr>`
    
    1. Display a standard hexdump of memory at `<addr>`.
        
4. `search <pattern>`
    
    1. Search memory for a byte sequence, string, or integer.
        
    2. Example: `search "/bin/sh"` or `search 0xdeadbeef`.
        
5. `find_fake_fast <addr>`
    
    1. Find a size field near `<addr>` that can be used to forge a fake fastbin chunk (exploit dev).
        

## Heap Analysis (Glibc malloc)

`pwndbg` excels at heap visualization. These commands replace manual inspection of `malloc` structures.

1. `heap`
    
    1. Print a summary of the heap state.
        
2. `bins`
    
    1. Print the status of all free bins (tcache, fastbins, unsorted, small, large).
        
3. `arena`
    
    1. Show details of the main arena structure.
        
4. `vis_heap_chunks` (or `vis`)
    
    1. Visualize the heap layout in color, distinguishing allocated vs. free chunks.
        
5. `malloc_chunk <addr>`
    
    1. Interpret memory at `<addr>` as a `malloc_chunk` struct and print fields (prev_size, size, flags).
        
6. `find_fake_fast <addr>`
    
    1. Search for a location near `<addr>` suitable for a fake fastbin chunk.
        

## Exploit Development Helpers

Tools specifically for generating payloads and finding offsets.

1. `cyclic <n>`
    
    1. Generate a De Bruijn sequence of length `<n>` (e.g., `cyclic 100` produces `aaaabaaacaaa...`).
        
2. `cyclic -l <value>`
    
    1. Find the offset of a value inside the generated sequence.
        
    2. Example: Crash the app with `cyclic`, then `cyclic -l 0x6161616c` to find the buffer overflow offset.
        
3. `rop`
    
    1. Dump available ROP gadgets from the binary.
        
4. `rop --grep <inst>`
    
    1. Search for specific ROP gadgets (e.g., `rop --grep "pop rdi"`).
        
5. `shellcode`
    
    1. Generate or print shellcode for the current architecture.
        
6. `canary`
    
    1. Print the value of the stack canary if known.
        
7. `got`
    
    1. Print the Global Offset Table (GOT) entries and their resolved addresses.
        

## Breakpoints (Enhanced)

1. `break *<addr>`
    
    1. Standard GDB, but `pwndbg` validates the address against memory maps.
        
2. `hardware <addr>` (or `hb`)
    
    1. Set a hardware breakpoint (often more reliable for write-watchers).