## Configuration

1. `handle SIGALRM nostop print nopass`

	1. Don't stop on SIGALRM

## Starting GDB and Remote Debugging

These commands cover local execution and remote debugging using `gdbserver`.

1. `gdb <program>`
    
    1. Start GDB with the specified executable.
        
2. `gdb --args <program> <arg1> <arg2>`
    
    1. Start GDB and automatically pass arguments to the program upon running.
        
3. `gdb -p <pid>`
    
    1. Attach GDB to an already running process identified by its Process ID.
        
4. `gdbserver :<port> <program>`
    
    1. **(Target Machine)** Start the program on the target machine and wait for a connection on the specified port.
        
5. `target remote <ip>:<port>`
    
    1. **(Host Machine)** Connect your local GDB instance to the remote `gdbserver`.
        
6. `run`
    
    1. Start the program execution from inside GDB.
        
7. `run <arg1> <arg2>`
    
    1. Start the program with specific arguments (overrides `--args`).
        
8. `run < input.txt`
    
    1. Start the program and pipe contents of `input.txt` into stdin.
        

## Inspection and Information

These commands provide context about the current state, stack, and threads.

1. `info args`
    
    1. Display the arguments passed to the current stack frame.
        
2. `info locals`
    
    1. Display the local variables defined in the current stack frame.
        
3. `info threads`
    
    1. List all currently running threads.
        
4. `thread <id>`
    
    1. Switch context to a specific thread ID.
        
5. `backtrace` or `bt`
    
    1. Show the call stack (chain of function calls).
        
6. `bt full`
    
    1. Show the call stack with local variables for each frame.
        
7. `frame`
    
    1. Show a summary of the current stack frame.
        
8. `frame <n>`
    
    1. Switch context to stack frame number `<n>`.
        
9. `up`
    
    1. Move one frame up the stack (towards caller).
        
10. `down`
    
    1. Move one frame down the stack (towards callee).
        
11. `info breakpoints`
    
    1. List all set breakpoints and watchpoints.
        

## Breakpoints and Watchpoints

Control where the program stops based on location or data changes.

1. `break <function>`
    
    1. Set a breakpoint at the entry of a function (e.g., `break main`).
        
2. `break <line>`
    
    1. Set a breakpoint at a specific line number.
        
3. `break *<address>`
    
    1. Set a breakpoint at a specific memory address (e.g., `break *0x4005c0`).
        
4. `break <file>:<line>`
    
    1. Set a breakpoint at a line in a specific file.
        
5. `break <location> if <condition>`
    
    1. Set a conditional breakpoint (e.g., `break 10 if i == 5`).
        
6. `watch <variable>`
    
    1. Pause execution when a variable is written to.
        
7. `watch *<address>`
    
    1. Pause execution when a memory address is modified.
        
8. `delete <id>`
    
    1. Delete the breakpoint with the specified ID.
        
9. `disable <id>`
    
    1. Temporarily disable a breakpoint.
        
10. `enable <id>`
    
    1. Re-enable a disabled breakpoint.
        

## Execution Control

Navigate through code execution once paused.

1. `continue` or `c`
    
    1. Resume execution until the next breakpoint.
        
2. `step` or `s`
    
    1. Step into the next line of code (enters functions).
        
3. `stepi` or `si`
    
    1. Step exactly one assembly instruction (enters calls).
        
4. `next` or `n`
    
    1. Step over the next line of code (executes functions without entering).
        
5. `nexti` or `ni`
    
    1. Step over the next assembly instruction.
        
6. `finish`
    
    1. Run until the current function returns.
        
7. `until <line>`
    
    1. Run until the program reaches a specific source line.
        

## Examining Memory

Use the `x` command: `x/<count><format><size> <address>`.  
**Sizes:** `b` (byte), `h` (halfword), `w` (word), `g` (giant/8 bytes).

1. `x/10xw $sp`
    
    1. Print the top 10 words of the stack in hex.
        
2. `x/s <address>`
    
    1. Print a null-terminated string at the address.
        
3. `x/c <address>`
    
    1. Print a single byte as an ASCII character.
        
4. `x/16cb <address>`
    
    1. Print 16 bytes consecutively as ASCII characters (useful for seeing buffers that aren't null-terminated strings).
        
5. `x/i $pc`
    
    1. Print the assembly instruction at the program counter.
        
6. `x/10i $pc`
    
    1. Print the next 10 assembly instructions starting from the program counter.[](https://visualgdb.com/gdbreference/commands/x)​
        
7. `x/gb <address>`
    
    1. Print one giant (8 bytes) as hex.
        
8. `x/4db <address>`
    
    1. Print 4 bytes as signed decimal numbers.
        
9. `print *(struct <name> *) <address>`
    
    1. Cast a specific memory address to a C structure and display its fields (e.g., `print *(struct user *) 0x602010`).
        
10. `set {char[4]} 0x8040000 = "Ace"`
    
    1. Write a string directly to a specific memory address.​
        

## Registers and Flags

Inspect and modify CPU registers and status flags. For x86/x64, flags are bits in the `EFLAGS` register.

**Flag Bit Positions:**

- **CF** (Carry Flag): Bit 0
    
- **PF** (Parity Flag): Bit 2
    
- **AF** (Auxiliary Flag): Bit 4
    
- **ZF** (Zero Flag): Bit 6
    
- **SF** (Sign Flag): Bit 7
    
- **TF** (Trap Flag): Bit 8
    
- **IF** (Interrupt Flag): Bit 9
    
- **DF** (Direction Flag): Bit 10
    
- **OF** (Overflow Flag): Bit 11
    

1. `info registers`
    
    1. Display general-purpose registers.
        
2. `print $rax`
    
    1. Print the value of the RAX register.
        
3. `set $rax = 0`
    
    1. Change the value of RAX to 0.
        
4. `info registers eflags`
    
    1. View the parsed CPU flags (displays active flags like `[ ZF SF ]`).
        
5. `print $eflags`
    
    1. View the raw integer value of the EFLAGS register.
        
6. `set $eflags |= (1 << 0)`
    
    1. Set **Carry Flag (CF)** to 1.
        
7. `set $eflags |= (1 << 6)`
    
    1. Set **Zero Flag (ZF)** to 1.
        
8. `set $eflags |= (1 << 7)`
    
    1. Set **Sign Flag (SF)** to 1.
        
9. `set $eflags |= (1 << 11)`
    
    1. Set **Overflow Flag (OF)** to 1.
        
10. `set $eflags &= ~(1 << 10)`
    
    1. Clear **Direction Flag (DF)** to 0.
        
11. `set $eflags ^= (1 << 6)`
    
    1. Toggle the **Zero Flag (ZF)** (flip 0 to 1, or 1 to 0).
        

## Calling Conventions (Parameter Passing)

Reference for where function arguments and return values are stored by default for common architectures.

1. **x86_64 System V ABI (Linux, macOS, BSD)**
    
    1. **Arg 1:** `RDI`
        
    2. **Arg 2:** `RSI`
        
    3. **Arg 3:** `RDX`
        
    4. **Arg 4:** `RCX`
        
    5. **Arg 5:** `R8`
        
    6. **Arg 6:** `R9`
        
    7. **Args 7+:** Pushed to Stack (Right-to-Left)
        
    8. **Return Value:** `RAX`
        
2. **x86_64 Microsoft x64 (Windows)**
    
    1. **Arg 1:** `RCX`
        
    2. **Arg 2:** `RDX`
        
    3. **Arg 3:** `R8`
        
    4. **Arg 4:** `R9`
        
    5. **Args 5+:** Pushed to Stack
        
    6. **Return Value:** `RAX`
        
3. **x86 32-bit (cdecl / stdcall)**
    
    1. **Args:** All arguments pushed to Stack (Right-to-Left)
        
    2. **Return Value:** `EAX`
        
4. **ARM64 (AArch64)**
    
    1. **Args 1-8:** `X0` through `X7`
        
    2. **Args 9+:** Pushed to Stack
        
    3. **Return Value:** `X0`
        

## Calling Functions Manually

You can invoke functions present in the binary directly from the debugger.

1. `call <function_name>(<arg1>, <arg2>)`
    
    1. Call a function defined in the program with the specified arguments. The return value is printed (if any).
        
2. `print <function_name>(<arg1>)`
    
    1. Similar to `call`, acts as an expression evaluation that runs the function and prints the result.
        
3. `set $rax = (long) malloc(1024)`
    
    1. Example: Allocate 1024 bytes of memory inside the debugged program and store the pointer in RAX.