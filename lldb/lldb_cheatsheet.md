## Starting LLDB and Remote Debugging

These commands cover local execution and remote debugging using `lldb-server` or `debugserver`.

1. `lldb <program>`
    
    1. Start LLDB with the specified executable.
        
2. `lldb -- <program> <arg1> <arg2>`
    
    1. Start LLDB and automatically pass arguments to the program upon running (note the double dash `--`).
        
3. `lldb -p <pid>`
    
    1. Attach LLDB to an already running process identified by its Process ID.
        
4. `lldb-server platform --server --listen *:<port>`
    
    1. **(Target Machine - Linux)** Start the server on the target machine.
        
5. `debugserver 0.0.0.0:<port> <program>`
    
    1. **(Target Machine - macOS/iOS)** Start the server on the target machine.
        
6. `process connect connect://<ip>:<port>`
    
    1. **(Host Machine)** Connect your local LLDB instance to the remote server.
        
7. `run` or `r`
    
    1. Start the program execution from inside LLDB.
        
8. `process launch -- <arg1> <arg2>`
    
    1. Start the program with specific arguments.
        
9. `process launch --stdin input.txt`
    
    1. Start the program and pipe contents of `input.txt` into standard input.
        

## Inspection and Information

These commands provide context about the current state, stack, and threads.

1. `frame variable` (alias `v`)
    
    1. Display the arguments and local variables of the current stack frame.
        
2. `frame variable --no-args`
    
    1. Display only local variables (hide arguments).
        
3. `thread list`
    
    1. List all currently running threads.
        
4. `thread select <id>`
    
    1. Switch context to a specific thread ID.
        
5. `thread backtrace` (alias `bt`)
    
    1. Show the call stack (chain of function calls).
        
6. `thread backtrace all` (alias `bt all`)
    
    1. Show the call stack for all threads.
        
7. `frame info`
    
    1. Show a summary of the current stack frame.
        
8. `frame select <n>`
    
    1. Switch context to stack frame number `<n>`.
        
9. `up`
    
    1. Move one frame up the stack (towards caller).
        
10. `down`
    
    1. Move one frame down the stack (towards callee).
        
11. `breakpoint list`
    
    1. List all set breakpoints and watchpoints.
        

## Breakpoints and Watchpoints

Control where the program stops based on location or data changes.

1. `breakpoint set --name <function>` (alias `b <function>`)
    
    1. Set a breakpoint at the entry of a function (e.g., `b main`).
        
2. `breakpoint set --line <line>`
    
    1. Set a breakpoint at a specific line number in the current file.
        
3. `breakpoint set --address <address>` (alias `b -a <address>`)
    
    1. Set a breakpoint at a specific memory address (e.g., `b -a 0x4005c0`).
        
4. `breakpoint set --file <file> --line <line>`
    
    1. Set a breakpoint at a line in a specific file.
        
5. `breakpoint modify -c '<condition>' <id>`
    
    1. Make an existing breakpoint conditional (e.g., `breakpoint modify -c 'i == 5' 1`).
        
6. `watchpoint set variable <variable>`
    
    1. Pause execution when a variable is written to.
        
7. `watchpoint set expression -- <address>`
    
    1. Pause execution when a memory address is modified (requires pointer size).
        
8. `breakpoint delete <id>`
    
    1. Delete the breakpoint with the specified ID.
        
9. `breakpoint disable <id>`
    
    1. Temporarily disable a breakpoint.
        
10. `breakpoint enable <id>`
    
    1. Re-enable a disabled breakpoint.
        

## Execution Control

Navigate through code execution once paused.

1. `continue` (alias `c`)
    
    1. Resume execution until the next breakpoint.
        
2. `thread step-in` (alias `s`)
    
    1. Step into the next line of code (enters functions).
        
3. `thread step-inst` (alias `si`)
    
    1. Step exactly one assembly instruction (enters calls).
        
4. `thread step-over` (alias `n`)
    
    1. Step over the next line of code (executes functions without entering).
        
5. `thread step-inst-over` (alias `ni`)
    
    1. Step over the next assembly instruction.
        
6. `thread step-out` (alias `finish`)
    
    1. Run until the current function returns.
        
7. `thread until <line>`
    
    1. Run until the program reaches a specific source line.
        

## Examining Memory

LLVM uses `memory read`, but supports GDB-style aliases like `x`.  
**Format flags:** `-f x` (hex), `-f d` (decimal), `-f c` (char/ascii).  
**Size flags:** `-s 1` (byte), `-s 2` (halfword), `-s 4` (word), `-s 8` (giant).

1. `memory read -s4 -f x -c 10 $sp` (alias `x/10xw $sp`)
    
    1. Print the top 10 words (4 bytes) of the stack in hex.
        
2. `memory read -f s <address>` (alias `x/s <address>`)
    
    1. Print a null-terminated string at the address.
        
3. `memory read -f c <address>`
    
    1. Print a single byte as an ASCII character.
        
4. `memory read -c 16 -f c <address>`
    
    1. Print 16 bytes consecutively as ASCII characters.
        
5. `disassemble --pc` (alias `x/i $pc`)
    
    1. Print the assembly instructions surrounding the current program counter.
        
6. `memory read -s8 -f x <address>` (alias `x/gx <address>`)
    
    1. Print one giant (8 bytes) as hex.
        
7. `memory read -s1 -f d -c 4 <address>`
    
    1. Print 4 bytes as signed decimal numbers.
        
8. `expression -- (*(struct <name> *)<address>)`
    
    1. Cast a memory address to a structure and display fields (e.g., `expr -- (*(struct user *)0x602010)`).
        

## Registers and Flags

Inspect and modify CPU registers and status flags. LLDB uses `register read` and `expression` for manipulation.

**x86/64 Flags (RFLAGS):** CF(0), ZF(6), SF(7), OF(11).  
**ARM64 Flags (CPSR):** V(28), C(29), Z(30), N(31).

1. `register read`
    
    1. Display general-purpose registers.
        
2. `register read rax` (x86) or `register read x0` (ARM64)
    
    1. Print the value of a specific register.
        
3. `register write rax 0`
    
    1. Change the value of RAX to 0.
        
4. `register read rflags` (x86) or `register read cpsr` (ARM64)
    
    1. View the raw integer value and parsed flags of the status register.
        
5. `expression $rflags |= (1 << 6)`
    
    1. **(x86)** Set **Zero Flag (ZF)** to 1.
        
6. `expression $rflags &= ~(1 << 0)`
    
    1. **(x86)** Clear **Carry Flag (CF)** to 0.
        
7. `expression $cpsr |= (1 << 30)`
    
    1. **(ARM64)** Set **Zero Flag (Z)** to 1.
        
8. `expression $cpsr &= ~(1 << 29)`
    
    1. **(ARM64)** Clear **Carry Flag (C)** to 0.
        

## Calling Conventions (Parameter Passing)

Reference for where function arguments and return values are stored by default.

1. **ARM64 (Apple Silicon / Linux AArch64)**
    
    1. **Arg 1:** `X0`
        
    2. **Arg 2:** `X1`
        
    3. **Arg 3:** `X2`
        
    4. **Arg 4:** `X3`
        
    5. **Arg 5:** `X4`
        
    6. **Arg 6:** `X5`
        
    7. **Arg 7:** `X6`
        
    8. **Arg 8:** `X7`
        
    9. **Args 9+:** Pushed to Stack
        
    10. **Return Value:** `X0`
        
2. **x86_64 System V ABI (Linux, macOS, BSD)**
    
    1. **Arg 1:** `RDI`
        
    2. **Arg 2:** `RSI`
        
    3. **Arg 3:** `RDX`
        
    4. **Arg 4:** `RCX`
        
    5. **Arg 5:** `R8`
        
    6. **Arg 6:** `R9`
        
    7. **Args 7+:** Pushed to Stack (Right-to-Left)
        
    8. **Return Value:** `RAX`
        
3. **x86_64 Microsoft x64 (Windows)**
    
    1. **Arg 1:** `RCX`
        
    2. **Arg 2:** `RDX`
        
    3. **Arg 3:** `R8`
        
    4. **Arg 4:** `R9`
        
    5. **Args 5+:** Pushed to Stack
        
    6. **Return Value:** `RAX`
        

## Calling Functions Manually

You can invoke functions present in the binary directly from the debugger using the `expression` command.

1. `expression -- <function_name>(<arg1>, <arg2>)`
    
    1. Call a function defined in the program with the specified arguments.
        
2. `p <function_name>(<arg1>)`
    
    1. Alias for `expression --`. Runs the function and prints the result.
        
3. `expression -- (void*)malloc(1024)`
    
    1. Example: Allocate 1024 bytes of memory inside the debugged program.
