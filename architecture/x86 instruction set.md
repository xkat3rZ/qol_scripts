## **1. Architecture Overview & Data Representation**

Before analyzing instructions, it is crucial to understand the environment in which they operate. The x86-64 architecture extends the legacy 32-bit (IA-32) architecture to 64-bit linear address space.[ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/9cd02621-f8a4-42b8-889b-31b2e02a8ef8/325462-sdm-vol-1-2abcd-3abcd-4.pdf)​

**1.1 Register Set**

- **General Purpose Registers (GPRs):** Extended to 64 bits. The prefix `R` denotes 64-bit (e.g., `RAX`), `E` denotes 32-bit (e.g., `EAX`). New registers `R8` through `R15` were added.
    
    - `RAX`: Accumulator (used in arithmetic, function return values).
        
    - `RBX`: Base (often used as a pointer).
        
    - `RCX`: Counter (loop counters, string operations).
        
    - `RDX`: Data (I/O, multiply/divide operations).
        
    - `RSI`/`RDI`: Source/Destination Indexes (string operations, function arguments in System V ABI).
        
    - `RSP`/`RBP`: Stack Pointer / Base Pointer.[ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/30ab4079-9b78-42db-85dd-ac213d614032/The-BOOK-of...-Randall-Hyde-The-Art-of-64-Bit-Assembly.-Volume-1_-x86-64-Machine-Organization-and-Programming-2021-No-Starch-Press-libgen.li.pdf)​
        
- **Instruction Pointer (`RIP`):** Holds the address of the next instruction to execute.
    

**1.2 The `EFLAGS` Register**  
Conditional instructions rely on status flags updated by arithmetic and logic operations.[ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/30ab4079-9b78-42db-85dd-ac213d614032/The-BOOK-of...-Randall-Hyde-The-Art-of-64-Bit-Assembly.-Volume-1_-x86-64-Machine-Organization-and-Programming-2021-No-Starch-Press-libgen.li.pdf)​

- **ZF (Zero Flag):** Set if the result is zero.
    
- **SF (Sign Flag):** Set if the result is negative (MSB is 1).
    
- **CF (Carry Flag):** Set if an unsigned arithmetic operation overflows/underflows.
    
- **OF (Overflow Flag):** Set if a signed arithmetic operation overflows.
    

**1.3 Addressing Modes**  
Efficient instruction usage requires understanding how operands are located.[ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/30ab4079-9b78-42db-85dd-ac213d614032/The-BOOK-of...-Randall-Hyde-The-Art-of-64-Bit-Assembly.-Volume-1_-x86-64-Machine-Organization-and-Programming-2021-No-Starch-Press-libgen.li.pdf)​

- **Immediate:** `mov rax, 100` (Data is encoded in the instruction).
    
- **Register:** `mov rax, rbx` (Data is in a register).
    
- **Direct (Displacement):** `mov rax, [variable]` (Access memory at a specific address).
    
- **Register Indirect:** `mov rax, [rbx]` (Access memory at address held in `RBX`).
    
- **Base + Index + Displacement:** `mov rax, [rbx + rsi*4 + 16]` (Used for array access).
    

---

## **2. Data Transfer Instructions**

These instructions move data between registers, memory, and the stack without affecting status flags (mostly).

**2.1 `MOV` - Move Data**  
Copies data from a source to a destination. The operands must be the same size. It cannot move memory to memory directly.[ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/9cd02621-f8a4-42b8-889b-31b2e02a8ef8/325462-sdm-vol-1-2abcd-3abcd-4.pdf)​

- **Syntax:** `MOV dest, src`
    
- **Examples:**
    
    text
    
    `mov eax, 5          ; Load immediate value 5 into EAX mov rbx, rax        ; Copy value from RAX to RBX mov [rcx], al       ; Store the low byte of RAX into memory at address in RCX mov r8d, [var]      ; Load 32-bit value from memory variable 'var'`
    
- **Note:** In 64-bit mode, moving a 32-bit value into a 64-bit register (e.g., `MOV EAX, 1`) automatically zero-extends the upper 32 bits of the register (RAX becomes 1).[ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/9cd02621-f8a4-42b8-889b-31b2e02a8ef8/325462-sdm-vol-1-2abcd-3abcd-4.pdf)​
    

**2.2 `MOVZX` / `MOVSX` - Move with Extension**  
Essential for converting smaller data types (byte/word) to larger ones (dword/qword).

- **`MOVZX` (Zero Extend):** Used for unsigned numbers. Fills upper bits with zeros.
    
- **`MOVSX` (Sign Extend):** Used for signed numbers. Fills upper bits with the sign bit (MSB) of the source.[ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/30ab4079-9b78-42db-85dd-ac213d614032/The-BOOK-of...-Randall-Hyde-The-Art-of-64-Bit-Assembly.-Volume-1_-x86-64-Machine-Organization-and-Programming-2021-No-Starch-Press-libgen.li.pdf)​
    
- **Examples:**
    
    text
    
    `mov bl, -5          ; BL = 0xFB (unsigned 251, signed -5) movzx rax, bl       ; RAX = 0x00000000000000FB (251) movsx rax, bl       ; RAX = 0xFFFFFFFFFFFFFFFB (-5)`
    

**2.3 `XCHG` - Exchange**  
Swaps the contents of two operands. Useful for endian conversion (16-bit) or atomic locks.[ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/30ab4079-9b78-42db-85dd-ac213d614032/The-BOOK-of...-Randall-Hyde-The-Art-of-64-Bit-Assembly.-Volume-1_-x86-64-Machine-Organization-and-Programming-2021-No-Starch-Press-libgen.li.pdf)​

- **Syntax:** `XCHG op1, op2`
    
- **Example:**
    
    text
    
    `xchg rax, rbx       ; Values in RAX and RBX are swapped xchg al, ah         ; Swap bytes in AX (endianness conversion)`
    

**2.4 `PUSH` and `POP` - Stack Operations**  
Used to save register states or pass arguments. The stack grows downward in memory.[ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/30ab4079-9b78-42db-85dd-ac213d614032/The-BOOK-of...-Randall-Hyde-The-Art-of-64-Bit-Assembly.-Volume-1_-x86-64-Machine-Organization-and-Programming-2021-No-Starch-Press-libgen.li.pdf)​

- **`PUSH src`:** Decrements `RSP` by operand size (8 for 64-bit), then writes `src` to `[RSP]`.
    
- **`POP dest`:** Reads from `[RSP]` into `dest`, then increments `RSP`.
    
- **Examples:**
    
    text
    
    `push rax            ; Save RAX to stack pop rbx             ; Restore top of stack into RBX`
    

---

## **3. Arithmetic Instructions**

These instructions perform mathematical operations and update the EFLAGS register (`ZF`, `SF`, `CF`, `OF`).

**3.1 `ADD` and `SUB`**  
Basic integer addition and subtraction.[ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/30ab4079-9b78-42db-85dd-ac213d614032/The-BOOK-of...-Randall-Hyde-The-Art-of-64-Bit-Assembly.-Volume-1_-x86-64-Machine-Organization-and-Programming-2021-No-Starch-Press-libgen.li.pdf)​

- **Syntax:** `ADD dest, src` / `SUB dest, src`
    
- **Operation:** `dest = dest + src` / `dest = dest - src`
    
- **Examples:**
    
    text
    
    `mov eax, 10 add eax, 5          ; EAX = 15 sub eax, 20         ; EAX = -5 (Sets SF=1, CF=1 due to borrow)`
    

**3.2 `INC` and `DEC`**  
Increment or decrement by 1. These are optimized but **do not** affect the Carry Flag (CF).[ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/9cd02621-f8a4-42b8-889b-31b2e02a8ef8/325462-sdm-vol-1-2abcd-3abcd-4.pdf)​

- **Syntax:** `INC dest` / `DEC dest`
    
- **Example:**
    
    text
    
    `inc rcx             ; RCX = RCX + 1 dec byte ptr [rbx]  ; Decrement the byte at memory address RBX`
    

**3.3 `MUL` and `IMUL` - Multiplication**  
x86 distinguishes between unsigned (`MUL`) and signed (`IMUL`) multiplication.[ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/30ab4079-9b78-42db-85dd-ac213d614032/The-BOOK-of...-Randall-Hyde-The-Art-of-64-Bit-Assembly.-Volume-1_-x86-64-Machine-Organization-and-Programming-2021-No-Starch-Press-libgen.li.pdf)​

- **`MUL` (Unsigned):** Always uses the Accumulator (`AL`/`AX`/`EAX`/`RAX`).
    
    - `mul bl` -> `AX = AL * BL`
        
    - `mul rbx` -> `RDX:RAX = RAX * RBX` (128-bit result split across two registers).
        
- **`IMUL` (Signed):** Has versatile forms (1, 2, or 3 operands).
    
    - 1-operand: Behaves like `MUL` but signed.
        
    - 2-operand: `imul reg, src` -> `reg = reg * src` (Truncates to fit dest).
        
    - 3-operand: `imul reg, src, imm` -> `reg = src * constant`.
        
- **Examples:**
    
    text
    
    `mov rax, 2 mov rbx, -3 imul rbx            ; RDX:RAX = -6 (Stored as 64-bit -6 in RAX, RDX extended) imul rcx, rbx, 10   ; RCX = RBX * 10 = -30`
    

**3.4 `DIV` and `IDIV` - Division**  
Divides a double-width value (dividend) by the source (divisor). Returns quotient and remainder.[ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/30ab4079-9b78-42db-85dd-ac213d614032/The-BOOK-of...-Randall-Hyde-The-Art-of-64-Bit-Assembly.-Volume-1_-x86-64-Machine-Organization-and-Programming-2021-No-Starch-Press-libgen.li.pdf)​

- **Preparation:** You **must** extend the dividend before dividing.
    
    - Use `CBW` (byte to word), `CWD` (word to double), `CDQ` (double to quad), or `CQO` (quad to octal) to sign-extend `RAX` into `RDX` for signed division.
        
    - For unsigned, zero out `RDX` (`XOR RDX, RDX`).
        
- **Syntax:** `DIV src` / `IDIV src`
    
- **Registers:** `RDX:RAX` (128-bit) / `src` (64-bit) -> Quotient in `RAX`, Remainder in `RDX`.
    
- **Example:**
    
    text
    
    `mov rax, 100 mov rcx, 3 xor rdx, rdx        ; Clear RDX for unsigned division div rcx             ; RAX = 33 (quotient), RDX = 1 (remainder)`
    

**3.5 `NEG` - Negate**  
Performs Two's Complement (inverts bits and adds 1) to reverse the sign of an integer.[ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/30ab4079-9b78-42db-85dd-ac213d614032/The-BOOK-of...-Randall-Hyde-The-Art-of-64-Bit-Assembly.-Volume-1_-x86-64-Machine-Organization-and-Programming-2021-No-Starch-Press-libgen.li.pdf)​

- **Example:**
    
    text
    
    `mov eax, 5 neg eax             ; EAX = -5 (0xFFFFFFFB)`
    

---

## **4. Logical and Bitwise Instructions**

These manipulate individual bits and are used for masking, flags, and fast math optimization.

**4.1 `AND`, `OR`, `XOR`**  
Standard bitwise operations. They always clear `OF` and `CF`.[ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/30ab4079-9b78-42db-85dd-ac213d614032/The-BOOK-of...-Randall-Hyde-The-Art-of-64-Bit-Assembly.-Volume-1_-x86-64-Machine-Organization-and-Programming-2021-No-Starch-Press-libgen.li.pdf)​

- **`AND`:** Used to mask (clear) bits.
    
- **`OR`:** Used to set bits.
    
- **`XOR`:** Used to toggle bits or clear registers efficiently.
    
- **Examples:**
    
    text
    
    `and al, 0Fh         ; Keep lower 4 bits, clear upper 4 bits or al, 80h          ; Force the MSB (bit 7) to 1 xor rax, rax        ; Efficiently set RAX to 0 (Optimized by CPU)`
    

**4.2 `NOT`**  
Performs One's Complement (inverts all bits).[ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/30ab4079-9b78-42db-85dd-ac213d614032/The-BOOK-of...-Randall-Hyde-The-Art-of-64-Bit-Assembly.-Volume-1_-x86-64-Machine-Organization-and-Programming-2021-No-Starch-Press-libgen.li.pdf)​

- **Example:**
    
    text
    
    `mov al, 11000011b not al              ; AL = 00111100b`
    

**4.3 `TEST`**  
Performs a non-destructive `AND`. It updates flags (`ZF`, `SF`) based on the result but discards the result itself. Used often to check if a register is zero or if a specific bit is set.[ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/30ab4079-9b78-42db-85dd-ac213d614032/The-BOOK-of...-Randall-Hyde-The-Art-of-64-Bit-Assembly.-Volume-1_-x86-64-Machine-Organization-and-Programming-2021-No-Starch-Press-libgen.li.pdf)​

- **Example:**
    
    text
    
    `test rax, rax       ; Check if RAX is 0 jz IsZero           ; Jump if Zero Flag is set test al, 1          ; Check if number is odd (bit 0 set) jnz IsOdd`
    

**4.4 Shifts and Rotates (`SHL`, `SHR`, `SAL`, `SAR`)**  
Move bits left or right. Used for high-speed multiplication/division by powers of 2.

- **`SHL` / `SAL` (Shift Left):** Multiplies by 2. Zeros shift in from the right.
    
- **`SHR` (Shift Right):** Divides unsigned numbers by 2. Zeros shift in from the left.
    
- **`SAR` (Shift Arithmetic Right):** Divides signed numbers by 2. The sign bit (MSB) shifts in to preserve the sign.
    
- **Examples:**
    
    text
    
    `mov eax, 1 shl eax, 2          ; EAX = 4 (1 * 2^2) mov eax, -8 sar eax, 1          ; EAX = -4 (Preserves negative sign)`
    

---

## **5. Control Flow Instructions**

These instructions alter `RIP` to create loops, branches, and function calls.

**5.1 `CMP` - Compare**  
Performs a non-destructive subtraction (`dest - src`). It sets flags but does not modify operands.[ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/30ab4079-9b78-42db-85dd-ac213d614032/The-BOOK-of...-Randall-Hyde-The-Art-of-64-Bit-Assembly.-Volume-1_-x86-64-Machine-Organization-and-Programming-2021-No-Starch-Press-libgen.li.pdf)​

- **Example:**
    
    text
    
    `cmp rax, 10         ; Compute RAX - 10 je  EqualLabel      ; Jump if result was 0 (RAX == 10) jl  LessLabel       ; Jump if result negative (RAX < 10, signed)`
    

**5.2 `JMP` - Unconditional Jump**  
Always transfers control to the target label.

- **Example:** `jmp TargetLabel`
    

**5.3 `Jcc` - Conditional Jumps**  
Jump only if specific flags are set.[ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/30ab4079-9b78-42db-85dd-ac213d614032/The-BOOK-of...-Randall-Hyde-The-Art-of-64-Bit-Assembly.-Volume-1_-x86-64-Machine-Organization-and-Programming-2021-No-Starch-Press-libgen.li.pdf)​

|Mnemonic|Meaning|Condition (Flags)|Use Case|
|---|---|---|---|
|**JE / JZ**|Jump Equal / Zero|ZF=1|`CMP` equal / `TEST` zero|
|**JNE / JNZ**|Jump Not Equal / Not Zero|ZF=0|`CMP` not equal|
|**JG / JNLE**|Jump Greater|ZF=0 and SF=OF|Signed comparisons|
|**JL / JNGE**|Jump Less|SF ≠ OF|Signed comparisons|
|**JA / JNBE**|Jump Above|CF=0 and ZF=0|Unsigned comparisons|
|**JB / JNAE**|Jump Below|CF=1|Unsigned comparisons|

- **Example (If/Else logic):**
    
    text
    
    `cmp rax, rbx jg  Greater         ; If RAX > RBX (signed) jl  Lesser          ; If RAX < RBX (signed) je  Equal           ; If RAX == RBX`
    

**5.4 `CALL` and `RET`**  
Used for procedures (functions).[ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/9cd02621-f8a4-42b8-889b-31b2e02a8ef8/325462-sdm-vol-1-2abcd-3abcd-4.pdf)​

- **`CALL dest`:** Pushes `RIP` (return address) to the stack and jumps to `dest`.
    
- **`RET`:** Pops the return address from the stack into `RIP`, resuming execution after the call.
    

---

## **6. String Instructions**

Optimized instructions for moving or comparing blocks of memory. They use `RSI` (Source) and `RDI` (Destination) and increment/decrement them based on the Direction Flag (`DF`).

- **`REP` Prefix:** Repeats the instruction `RCX` times.
    
- **`MOVSB` / `MOVSW` / `MOVSD` / `MOVSQ`:** Move data from `[RSI]` to `[RDI]`.
    
- **`STOSB` / `STOSQ`:** Store `AL`/`RAX` value into `[RDI]`. Used for initializing memory (e.g., `memset`).
    
- **Example (Copying a string):**
    
    text
    
    `cld                 ; Clear Direction Flag (increment forward) mov rsi, source_ptr ; Source address mov rdi, dest_ptr   ; Destination address mov rcx, 10         ; Number of bytes to copy rep movsb           ; Copy 10 bytes from [RSI] to [RDI]`
    

---

## **Summary of Key Differences in 64-bit Mode**

1. **Operand Size:** Default is 32-bit. 64-bit operands require the `REX.W` prefix (handled by the assembler).
    
2. **Zero Extension:** Writing to a 32-bit register (e.g., `MOV EAX, 5`) zeroes the upper 32 bits of the 64-bit register (`RAX`).[ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/9cd02621-f8a4-42b8-889b-31b2e02a8ef8/325462-sdm-vol-1-2abcd-3abcd-4.pdf)​
    
3. **New Registers:** `R8`-`R15` are available but require REX prefixes for access.
    
4. **No `PUSH`/`POP` for 32-bit:** In 64-bit mode, you generally push/pop 64-bit values (`PUSH RAX`), not 32-bit (`PUSH EAX` is invalid).
    

5. [https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/9cd02621-f8a4-42b8-889b-31b2e02a8ef8/325462-sdm-vol-1-2abcd-3abcd-4.pdf](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/9cd02621-f8a4-42b8-889b-31b2e02a8ef8/325462-sdm-vol-1-2abcd-3abcd-4.pdf)
6. [https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/30ab4079-9b78-42db-85dd-ac213d614032/The-BOOK-of...-Randall-Hyde-The-Art-of-64-Bit-Assembly.-Volume-1_-x86-64-Machine-Organization-and-Programming-2021-No-Starch-Press-libgen.li.pdf](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/30ab4079-9b78-42db-85dd-ac213d614032/The-BOOK-of...-Randall-Hyde-The-Art-of-64-Bit-Assembly.-Volume-1_-x86-64-Machine-Organization-and-Programming-2021-No-Starch-Press-libgen.li.pdf)