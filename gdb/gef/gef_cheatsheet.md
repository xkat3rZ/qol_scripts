## Starting and Basic Setup

`gef` is a GDB plugin, so all standard GDB commands still work; these focus on extras added by `gef`.

1. `gef`
    
    1. Show the main `gef` help menu and list core features.
        
2. `gef config`
    
    1. Show or edit `gef` configuration options (colors, context layout, theme, etc.).
        
3. `gef missing`
    
    1. Check for missing external tools that integrate with `gef` (ropper, radare2, etc.).
        
4. `entry-break`
    
    1. Automatically set a breakpoint at the program entry point and run until there.
        

## Context and UI

`gef` heavily customizes the TUI-like context to show registers, disassembly, stack, and memory maps on each stop.

1. `context`
    
    1. Redisplay the context panes (registers, disasm, stack, memory map, etc.).
        
2. `context disable|enable <pane>`
    
    1. Enable or disable parts of the context (for example, `context disable memory`).
        
3. `theme`
    
    1. List or change UI theme elements such as colors and styles.
        
4. `registers`
    
    1. Print registers with flags and annotations in a compact, colorized format.
        

## Execution Control

These work alongside normal `run`, `next`, `step`, etc., but are tailored for exploit/reverse workflows.

1. `finish`
    
    1. Run until the current function returns (standard but commonly used with `gef`).
        
2. `stepuntil <addr>`
    
    1. Run until execution reaches a specific address.
        
3. `skipi <n>`
    
    1. Skip over the next `n` instructions without executing them.
        
4. `continue-until <symbol>`
    
    1. Continue until a given symbol is hit (for example, a specific function).
        

## Memory and Stack Inspection

`gef` provides richer memory inspection primitives than raw `x` while still supporting `x`.

1. `hexdump <addr> [len]`
    
    1. Display a colorized hexdump of memory at `<addr>` for `len` bytes (default length if omitted).
        
2. `dereference <addr> [count]`
    
    1. Recursively follow and print pointers from `<addr>`, similar to a smart “stack/heap telescope”.
        
3. `stack [count]`
    
    1. Show a nicely formatted view of the stack around the current stack pointer.
        
4. `xinfo <addr>`
    
    1. Show information about an address: section, permissions, mapping, symbol, etc.
        

## Memory Maps and Binaries

These commands help quickly understand the loaded binary and its memory layout.

1. `vmmap`
    
    1. Show the current process’ memory map (segments, permissions, file backing).
        
2. `elf-info`
    
    1. Display metadata about the main ELF binary (entry point, sections, PIE/RELRO, etc.).
        
3. `checksec`
    
    1. Display common binary protections (NX, PIE, RELRO, Canary, Fortify, etc.).
        
4. `got`
    
    1. Show Global Offset Table (GOT) entries and their current resolved addresses.
        
5. `plt`
    
    1. List the Procedure Linkage Table (PLT) functions and their addresses.
        

## Heap Analysis (glibc)

`gef` adds a suite of heap helpers when debugging glibc `malloc`-based programs.

1. `heap`
    
    1. Show a summary of the current heap state (main arena, top chunk, base, etc.).
        
2. `heap chunks`
    
    1. List heap chunks for the main arena, showing size, in-use/free flags, and addresses.
        
3. `heap bins`
    
    1. Show allocator bins (tcache, fastbins, small, large, unsorted) and their contents.
        
4. `heap arenas`
    
    1. List all arenas (main and thread-specific) with basic info.
        
5. `heap chunk <addr>`
    
    1. Interpret memory at `<addr>` as a malloc chunk and show its struct fields.
        

## Exploit Development Helpers

Common helpers for offset calculation, ROP, and pattern generation.

1. `pattern create <len>`
    
    1. Generate a cyclic pattern (De Bruijn sequence) of length `<len>` for overflow testing.
        
2. `pattern search <value>`
    
    1. Look up the offset of a crashed value (like an overwritten instruction pointer) in the last pattern.
        
3. `ropper`
    
    1. Launch `ropper` integration to search for ROP gadgets in loaded binaries and libraries.
        
4. `canary`
    
    1. Show the value of the current stack canary if it can be read.
        
5. `vmmap` plus `pattern`
    
    1. Combined usage: find where your pattern landed in memory and correlate with mappings to design payloads.
        

## Breakpoints and Watchpoints

`gef` mostly enhances display and convenience around standard break/watch commands.

1. `break <location>`
    
    1. Standard breakpoint, but `gef` will prettify the listing and annotate symbols.
        
2. `hbreak <location>`
    
    1. Set a hardware breakpoint on an address (useful when software breakpoints are unreliable).
        
3. `watch <expr>`
    
    1. Watch an expression or variable and break when it changes.
        
4. `rwatch <expr>` / `awatch <expr>`
    
    1. Break when a memory location is read (`rwatch`) or accessed (`awatch`).