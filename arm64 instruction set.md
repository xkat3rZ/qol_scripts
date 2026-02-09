### **1. Data Movement Instructions**

Data movement is fundamentally different in ARM64 compared to x86; you cannot move data directly from memory to memory. You must load into a register, manipulate, and store back.

#### **MOV / MVN (Move / Move Not)**
*   **Description:** Moves a value (immediate or register) into a destination register. `MVN` moves the bitwise inverse (NOT) of the value.
*   **Syntax:** `MOV Wd, Ws` or `MOV Xd, #imm`
*   **Source Context:** Used extensively in the `toupper` routine to set up system call parameters (File 1, Ch 6).

**Examples:**
```assembly
MOV X0, #1          ; Move immediate value 1 into 64-bit register X0 (File 1)
MOV W1, W2          ; Copy 32-bit value from W2 to W1
MVN W0, W1          ; Store the bitwise NOT of W1 into W0
MOV X2, XZR         ; Clear X2 by moving the Zero Register (XZR) into it
```

#### **MOVK / MOVZ / MOVN (Move Wide)**
*   **Description:** Used to construct 64-bit immediates that are too large for a single instruction.
    *   `MOVZ`: Move with Zero (clears other bits).
    *   `MOVK`: Move with Keep (keeps other bits, inserts 16-bit immediate).
    *   `MOVN`: Move with Not (loads inverted immediate).
*   **Source Context:** File 2 highlights these for loading 64-bit pointers or large constants.

**Examples:**
```assembly
MOVZ X0, #0xFFFF, LSL #16  ; Load 0xFFFF into bits 16-31, clear others
MOVK X0, #0x1234, LSL #0   ; Insert 0x1234 into bits 0-15, keep others
```

***

### **2. Memory Access Instructions (Load & Store)**

ARM64 uses a Load/Store architecture. To process data in memory, it must first be loaded into registers.

#### **LDR / STR (Load / Store Register)**
*   **Description:** Loads or stores a 32-bit (W) or 64-bit (X) word from/to memory.
*   **Addressing Modes:**
    *   *Base Register:* `[Xn]`
    *   *Offset:* `[Xn, #offset]`
    *   *Pre-indexed:* `[Xn, #offset]!` (Updates Xn before access)
    *   *Post-indexed:* `[Xn], #offset` (Updates Xn after access)
*   **Source Context:** The `copypage` routine (File 1, Ch 15) uses these to move 4KB pages.

**Examples:**
```assembly
LDR X0, [X1]        ; Load 64-bit word from address in X1
LDR W5, [X0, #4]    ; Load 32-bit word from address X0 + 4
STR X0, [SP, #-16]! ; Push X0 onto stack (Pre-indexed decrement)
LDR X0, [SP], #16   ; Pop X0 from stack (Post-indexed increment)
```

#### **LDP / STP (Load / Store Pair)**
*   **Description:** Loads or stores two registers in a single instruction. This is heavily used for stack operations to preserve register pairs and the Link Register (LR).
*   **Source Context:** Standard function prologue/epilogue in File 1.

**Examples:**
```assembly
STP X29, X30, [SP, #-16]! ; Save Frame Pointer (X29) and Link Register (X30)
LDP X29, X30, [SP], #16   ; Restore FP and LR and adjust stack
```

***

### **3. Arithmetic Instructions**

Arithmetic instructions usually operate on registers. They can optionally set condition flags (N, Z, C, V) if the 'S' suffix is used (e.g., `ADDS`).

#### **ADD / SUB (Add / Subtract)**
*   **Description:** Performs addition or subtraction.
*   **Syntax:** `ADD Rd, Rn, Operand2`
*   **Source Context:** Used in the `toupper` loop to increment pointers (File 1).

**Examples:**
```assembly
ADD X0, X1, #8      ; X0 = X1 + 8 (Increment pointer by 64 bits)
SUB W5, W5, #'a'-'A'; Convert lowercase to uppercase by subtracting offset
SUBS X1, X1, #1     ; Decrement X1 and set flags (useful for loops)
```

#### **MUL / MADD / MSUB (Multiply Operations)**
*   **Description:** `MUL` is an alias for `MADD` using the zero register.
    *   `MADD Rd, Rn, Rm, Ra` -> `Rd = Ra + (Rn * Rm)`
    *   `MSUB Rd, Rn, Rm, Ra` -> `Rd = Ra - (Rn * Rm)`
*   **Source Context:** File 2 (Ch 9) uses these for decimal-to-string conversion algorithms (division by constant multiplication).

**Examples:**
```assembly
MUL X0, X1, X2      ; X0 = X1 * X2
MADD X0, X1, X2, X3 ; X0 = X3 + (X1 * X2) (Multiply-Add)
```

***

### **4. Logical and Bit Manipulation**

File 2 ("The Art of ARM Assembly") provides extensive detail on bit manipulation, which is a strength of the ARM ISA.

#### **AND / ORR / EOR / BIC**
*   **Description:** Standard bitwise AND, OR, XOR (Exclusive OR), and Bit Clear (AND NOT).
*   **Source Context:** Used for masking bits or checking alignment.

**Examples:**
```assembly
AND X0, X0, #0xFF   ; Mask lower 8 bits (Keep only low byte)
ORR X1, X1, #0x80   ; Set bit 7
EOR X0, X0, X0      ; XOR with self clears register (equivalent to MOV 0)
BIC X0, X1, X2      ; X0 = X1 AND (NOT X2) (Clears bits set in X2)
```

#### **LSL / LSR / ASR / ROR (Shift and Rotate)**
*   **Description:** Logical Shift Left/Right, Arithmetic Shift Right (preserves sign), Rotate Right.
*   **Source Context:** Used in `u64ToBuf` (File 2) to isolate decimal digits.

**Examples:**
```assembly
LSL X0, X1, #2      ; Logical Shift Left by 2 (Multiply by 4)
ASR X0, X1, #1      ; Arithmetic Shift Right (Divide by 2, preserve sign)
ROR X0, X1, #4      ; Rotate Right by 4 bits
```

#### **UBFM / SBFM (Bitfield Moves)**
*   **Description:** The underlying instructions for most shift and extract aliases (`UBFX`, `SBFIZ`, etc.). They allow extracting a sequence of bits from a source and placing them anywhere in the destination.
*   **Source Context:** File 2 dedicates significant space to these for "bit twiddling."

**Examples:**
```assembly
UBFX X0, X1, #8, #4 ; Unsigned Bitfield Extract: Take 4 bits from X1 starting at bit 8, place in X0 at bit 0.
```

***

### **5. Control Flow Instructions**

These instructions control the execution path (branches, loops, function calls).

#### **B / BL / RET (Branching)**
*   **Description:**
    *   `B`: Unconditional branch (Jump).
    *   `BL`: Branch with Link (Call subroutine; saves return address in X30/LR).
    *   `RET`: Return from subroutine (Jumps to address in X30).
*   **Source Context:** `main.s` calls `toupper` using `BL` (File 1, Ch 6).

**Examples:**
```assembly
B loop_start        ; Jump to label 'loop_start'
BL printf           ; Call printf function (stores return addr in LR)
RET                 ; Return from function
```

#### **CBZ / CBNZ (Compare and Branch)**
*   **Description:** Compare to Zero and Branch. Efficient instructions that combine a comparison and a jump.
*   **Source Context:** Checking for null terminators in strings (File 1).

**Examples:**
```assembly
CBZ W0, end_process ; If W0 is 0, branch to 'end_process'
CBNZ X1, loop_body  ; If X1 is NOT 0, branch to 'loop_body'
```

#### **CMP / CSEL (Compare and Select)**
*   **Description:** `CMP` subtracts two values to set flags. `CSEL` selects between two registers based on those flags, avoiding expensive branches.
*   **Source Context:** Optimized logic to avoid pipeline flushes (File 2).

**Examples:**
```assembly
CMP X0, X1          ; Compare X0 and X1 (updates flags)
CSEL X2, X0, X1, GT ; If Greater Than (GT), X2 = X0; else X2 = X1
```

***

### **6. SIMD / NEON Instructions (Advanced)**

File 1 (Ch 13) and File 2 describe the NEON coprocessor for parallel data processing (Single Instruction, Multiple Data). These instructions typically use `V` or `Q` registers.

#### **LD1 / ST1 (Vector Load / Store)**
*   **Description:** Loads/Stores multiple elements into vector registers.
*   **Source Context:** Matrix multiplication examples in File 1.

**Examples:**
```assembly
LD1 {V0.4S}, [X0]   ; Load four 32-bit floats from [X0] into V0
ST1 {V0.16B}, [X1]  ; Store 16 bytes from V0 to [X1]
```

#### **FADD / FMUL (Floating Point)**
*   **Description:** Standard floating-point arithmetic on scalar (S/D) or vector (V) registers.
*   **Source Context:** Distance calculations (File 1, Ch 13).

**Examples:**
```assembly
FADD S0, S1, S2     ; Add single-precision float S1 and S2
FMUL V0.4S, V1.4S, V2.4S ; Multiply 4 float pairs in parallel
```

#### **TBL / TBX (Table Lookup)**
*   **Description:** Powerful vector permutation instructions. Uses a vector as an index to look up bytes in another vector.
*   **Source Context:** File 2 describes using this for complex shuffling or endian swapping.

**Example:**
```assembly
TBL V0.8B, {V1.16B}, V2.8B ; Look up bytes from V1 using indices in V2, store in V0
```

***

### **7. System Instructions**

#### **SVC (Supervisor Call)**
*   **Description:** Triggers an exception to call the operating system kernel (syscall).
*   **Source Context:** Used in `main.s` to write to stdout or exit the program (File 1).

**Example:**
```assembly
MOV X8, #64         ; Syscall number for 'write' (Linux)
MOV X0, #1          ; File descriptor (stdout)
SVC #0              ; Invoke kernel
```

#### **ADR / ADRP (Address Generation)**
*   **Description:** Calculates the address of a label. `ADRP` (Page) is used for position-independent code (PIC) to get the 4KB page base, often followed by `ADD`.
*   **Source Context:** Accessing global variables like `instr` or `outstr` in File 1.

**Example:**
```assembly
ADRP X0, msg_label  ; Get page address of message
ADD X0, X0, :lo12:msg_label ; Add lower 12-bit offset
```

***
### **8. Registers** [^3]

ARM64 (also known as AArch64) uses a standardized calling convention defined in the Procedure Call Standard for the ARM 64-bit Architecture (AAPCS64).
#### Register Usage

##### General-Purpose Registers

- **x0-x7**: Used for passing the first 8 integer or pointer arguments to functions. These registers are also used for return values, with x0 containing the primary return value.[](https://hackeradam.com/aarch64-calling-conventions/)
    
- **x8**: Serves as an indirect result location register, used when returning structures larger than 16 bytes.[](https://duetorun.com/blog/20230615/a64-pcs-demo/)
    
- **x9-x15**: Temporary (caller-saved) registers that can be used freely within a function without preservation.[](https://dede.dev/posts/ARM64-Calling-Convention-Cheat-Sheet/)
    
- **x16-x17**: Intra-procedure-call temporary registers.[](https://student.cs.uwaterloo.ca/~cs452/docs/rpi4b/aapcs64.pdf)​
    
- **x19-x29**: Callee-saved registers that must be preserved and restored by the called function if used.[](https://stackoverflow.com/questions/68721134/linux-arm64-calling-convention-what-registers-need-saving-by-callee)
    
- **x29**: Frame pointer (FP).[](https://student.cs.uwaterloo.ca/~cs452/docs/rpi4b/aapcs64.pdf)​
    
- **x30**: Link register (LR), holds the return address.[](https://duetorun.com/blog/20230615/a64-pcs-demo/)​
    
- **sp**: Stack pointer, must remain 16-byte aligned.[](https://student.cs.uwaterloo.ca/~cs452/docs/rpi4b/aapcs64.pdf)​
    
#### Vector/SIMD Registers

- **v0-v7**: Used for passing the first 8 floating-point or SIMD arguments. Also used for floating-point return values.[](https://hackeradam.com/aarch64-calling-conventions/)
    
- **v8-v15**: Lower 64 bits must be preserved by callee if used.[](https://student.cs.uwaterloo.ca/~cs452/docs/rpi4b/aapcs64.pdf)​
    
- **v16-v31**: Temporary registers that don't need preservation.[](https://student.cs.uwaterloo.ca/~cs452/docs/rpi4b/aapcs64.pdf)​
    
#### Argument Passing

##### Standard Functions

- The first 8 integer/pointer arguments go in x0-x7[](https://dede.dev/posts/ARM64-Calling-Convention-Cheat-Sheet/)
    
- The first 8 floating-point/SIMD arguments go in v0-v7[](https://hackeradam.com/aarch64-calling-conventions/)
    
- Additional arguments beyond the first 8 are passed on the stack[](https://duetorun.com/blog/20230615/a64-pcs-demo/)
    
- Stack arguments are pushed in reverse order, with each argument occupying at least 8 bytes (even if smaller)[](https://duetorun.com/blog/20230615/a64-pcs-demo/)​
    
#### Variadic Functions

For functions with variable arguments (using `...`), some implementations like ARM64EC use only the first 4 registers (x0-x3) for parameter passing, with remaining parameters spilled to the stack.[](https://learn.microsoft.com/en-us/windows/arm/arm64ec-abi)​

#### Return Values

- Integer and pointer return values use x0 (or x0-x1 for larger values)[](https://cintaprogramming.com/2022/01/16/calling-convention-pada-amd64-arm64-dan-riscv64/)
    
- Floating-point return values use v0[](https://student.cs.uwaterloo.ca/~cs452/docs/rpi4b/aapcs64.pdf)​
    
- Structures larger than 16 bytes are returned via memory pointed to by x8[](https://dede.dev/posts/ARM64-Calling-Convention-Cheat-Sheet/)
    
#### Stack Alignment

The stack pointer must be 16-byte aligned at public function call boundaries. When allocating stack space for arguments, the total allocation must be a multiple of 16 bytes.

[1](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/c32db14c-8159-4753-8060-75e3a784fad2/Stephen-Smith-Programming-with-64-Bit-ARM-Assembly-Language_-Single-Board-Computer-Development-for-Raspberry-Pi-and-Mobile-Devices-2020-Apress-10.1007_978-1-4842-5881-1-libgen.li-1.pdf)
[2](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/95d63b2c-f3a2-4f56-98eb-1353676524c4/The-Art-of-ARM-Assembly-Volume-1-for-Candi-Bara.pdf)
[3](https://ohyaan.github.io/assembly/functions_and_stack_management_in_arm64_assembly/#aapcs64-overview)