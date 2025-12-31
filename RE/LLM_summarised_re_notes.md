## Part I: The Golden Rules of Analysis

### 1. The "10-Minute Triage" Rule

Before launching a debugger or decompiler, spend 10 minutes performing static triage. This saves hours of wasted analysis later.

* **Strings are King:** Run `strings` (or use Ghidra/IDA Strings view). Look for:
    * **PDB Paths:** `C:\Users\Builder\Jenkins\ProjectX\...` reveals the username and project structure.
    * **URLs:** Hardcoded C2 domains, API endpoints, or update servers.
    * **Format Strings:** `%s:%d error` reveals the structure of data being logged.
    * **Typos:** Unique typos in error messages are excellent search terms for Google (to find open-source components) or to track the malware author’s identity.
* **Imports/Exports:**
    * **Import Table Hashing:** Check the "Imphash". Malware families often share the exact same import table hash even if the file hash changes.
    * **Functionality Guesses:**
        * `InternetOpen`, `HttpSendRequest` → Network capable.
        * `CreateService`, `StartService` → Persistence mechanism.
        * `CryptDecrypt`, `CryptAcquireContext` → Crypto usage (or packing).
        * `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` → Anti-analysis.
* **Entropy Check:**
    * **High Entropy (> 7.2):** The file is likely packed or encrypted. The code you see at the entry point is just a stub (unpacker). Don't analyze it statically; run it to the OEP (Original Entry Point).
    * **Low Entropy:** Standard compiled code. Safe to start static analysis immediately.


### 2. The "Naming Discipline" Trick

* **Never leave a function named `sub_XXXXXX`.** Even a bad name is better than no name.
* **Progressive Naming Strategy:**

1. **Level 1 (Behavioral):** `log_error?`, `crypto_routine?`, `file_reader?`. Use `?` for uncertainty.
2. **Level 2 (Contextual):** `config_parser_read_xml`, `network_send_heartbeat`.
3. **Level 3 (Verified):** `MD5_Update`, `AES_KeyGen`.
* **Tip:** If you see a function used in 50 places, rename it immediately. Even if you call it `Common_Utility_Function`, it cleans up the graph of 50 other functions.

***

## Part II: Low-Level Assembly Patterns (The "Eye" Test)

### 3. Arithmetic \& Logic Tricks

* **Clearing Registers:**
    * `XOR EAX, EAX` is the standard, optimized way to set a register to zero (smaller opcode than `MOV EAX, 0`).
    * **Tip:** If you see `XOR EAX, EAX` followed by `RET`, the function returns `0` (False/Success depending on context).
* **Setting -1 (All Ones):**
    * `OR EAX, -1` is a common optimization to set a register to `0xFFFFFFFF`.
* **Division by Multiplication (The "Magic Number" Trick):**
    * CPUs hate division (it's slow). Compilers replace it with multiplication by a "reciprocal" magic number.
    * **Heuristic:** If you see `MOV EAX, 0xAAAAAAAB` followed by `MUL`, the code is dividing by 3.
    * **Heuristic:** `0xCCCCCCCD` usually indicates division by 10.
    * **Action:** In IDA/Ghidra, comment "Division by X" on these lines to reduce cognitive load.


### 4. Control Flow Patterns

* **The "Diamond" Pattern:** A graph that splits into two and rejoins immediately is an `if-else` statement.
* **The "Switch" Jump Table:**
    * Look for `JMP [EAX*4 + 0x401000]`. This is a switch statement jumping to a table of addresses.
    * **IDA Tip:** If IDA doesn't recognize the switch, put your cursor on the `JMP` instruction and use **Edit -> Other -> Specify Switch Idiom**.
* **Loops:**
    * **While Loop:** A check at the start, a body, and a jump back to the start.
    * **Do-While Loop:** A body, and a check at the end to jump back.
    * **For Loop:** Initialization (once), Check (every time), Body, Increment, Jump back.


### 5. Function Calling Conventions (x86)

* **cdecl:** Arguments pushed on stack (Right-to-Left). Caller cleans the stack (`ADD ESP, 12` after call). Common in C/C++.
* **stdcall:** Arguments pushed on stack (Right-to-Left). Callee cleans the stack (`RET 12`). Common in Win32 APIs.
* **fastcall (Microsoft):** First two arguments in `ECX`, `EDX`. Rest on stack.
* **fastcall (GCC/Linux):** Arguments in `RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9`.
* **The "Thiscall" Trick:** If you see `MOV ECX, <Value>` immediately before a `CALL`, it is almost certainly a **C++ member function call**. `ECX` holds the `this` pointer.

***

## Part III: Advanced C++ Reversing

### 6. Identification of Classes

* **The "Constructor" Signature:**
    * A constructor's job is to initialize memory. The *first* thing it usually does is setup the **VTable**.
    * **Heuristic:** Look for a function that takes a pointer (in `ECX`) and immediately moves a constant address into `[ECX]`.
    * `MOV DWORD PTR [ECX], 0x402000` -> `0x402000` is the VTable address.
    * **Action:** Name the function `ClassX::ctor`. Name the data at `0x402000` `ClassX::vtable`.


### 7. Recovering Class Members

* **Offset Tracking:**
    * You see: `MOV [ECX+4], 10` and `MOV [ECX+8], EAX`.
    * **Interpretation:** The class has a member at offset 0x4 (int?) and offset 0x8.
    * **Action:** Create a struct in IDA/Ghidra. Add members at offsets 0, 4, 8. Apply this struct to the `ECX` variable. The code changes from `[ECX+4]` to `[ECX].m_counter`.
* **The "New" Operator:**
    * Code typically looks like: `PUSH 24` -> `CALL operator_new`.
    * **Interpretation:** The class size is 24 bytes. This confirms your struct should be approx 24 bytes large.


### 8. RTTI (Run-Time Type Information) - The Holy Grail

* If the application is compiled with MSVC and RTTI is enabled, you can recover **original class names** even in stripped binaries.
* **How to find it:**

1. Find the VTable.
2. Look at the 4 bytes *before* the VTable start. This is the **RTTI Complete Object Locator**.
3. Follow the pointers: `ObjectLocator` -> `TypeDescriptor` -> `Name`.
4. You will see strings like `.?.AVClassName@@`.
* **Automation:** Both Ghidra and IDA have scripts/plugins (like ClassInformer) to parse this automatically. **Run them first.**

***

## Part IV: IDA Pro Mastery (The "Surgeon's Scalpel")

### 9. View Management \& Navigation

* **Synchronized Views:** Always open "Hex View" and dock it next to "Disassembly". Go to **Options -> General -> Disassembly** and check "Sync with Hex View". When you click an opcode, you see the exact bytes. Essential for patching.
* **The "Breadcrumbs" (navigation history):**
    * `Esc` goes back. `Ctrl+Enter` goes forward.
    * **Tip:** If you get lost in a call graph, use the "Proximity View" to see parents/children relations visually.
* **Highlighting:** Click a register (e.g., `EAX`). IDA highlights all occurrences in the current function. This is the fastest way to trace data flow without a debugger.


### 10. Data Type Reconstruction

* **The "Y" Key (Type Declaration):**
    * Select a function name. Press `Y`. You can type a C-style declaration: `int __stdcall myFunc(char *name, int ID)`.
    * IDA will re-analyze all call sites and propagate these names to the arguments pushed on the stack!
* **Array Creation:**
    * You see a block of bytes that looks like a table. Move to the first byte. Press `*` (NumPad).
    * Uncheck "Create as array". Set "Number of elements".
    * **Trick:** If it's an array of pointers, press `O` (Offset) on the first element *before* creating the array. IDA is smart enough to create an "Array of Offsets".


### 11. FLIRT (Fast Library Identification and Recognition Technology)

* **The Problem:** You analyze a binary and see thousands of unnamed functions.
* **The Solution:** You might be analyzing the C Standard Library (libc) statically linked.
* **The Fix:** Open the Signatures window (`Shift+F5`). Right-click -> "Apply new signature".
    * Choose signatures that match the compiler (e.g., `vc14`, `gcc`, `delphi`).
    * **Magic:** `sub_401000` suddenly becomes `strcpy`. `sub_402500` becomes `printf`.
    * **Tip:** If no built-in signature works, use the **IDA SIGMake** tool to generate your own signatures from a known library `.lib` file.


### 12. Patching Binaries

* IDA is primarily an *analyzer*, not an editor. But you can patch.
* **Edit -> Patch Program -> Change Byte**: Modify the hex.
* **Edit -> Patch Program -> Assemble**: Type new assembly instructions (e.g., change `JZ` to `JMP`).
* **CRITICAL STEP:** Changes are only in the database. To save them, you must verify the patches and then apply them to the input file. (This workflow is often clunky; many reversers use IDA to find the offset, then use a hex editor to patch the file).

***

## Part V: Ghidra Mastery (The "Open Source Powerhouse")

### 13. Project Management Power

* **Archive Binaries:** Ghidra uses a project structure. Import *all* DLLs and the EXE into the same project folder.
* **Link Libraries:** When you analyze `MyApp.exe`, if `MyLib.dll` is in the project, Ghidra can resolve external calls between them.
* **Versioning:** Ghidra has built-in version control (like Git for binaries).
    * **Tip:** Before trying a risky script that renames 1,000 functions, hit "Checkpoint". If it messes up, roll back.


### 14. The Decompiler (The "P-Code" Magic)

* **Ghidra's Decompiler is Interactive:** It's not just text; it's a UI.
* **Rename Variables:** Highlight `iVar1` in the decompiler, press `L`, rename to `loop_counter`. It updates everywhere.
* **Retype Variables:** Right-click a variable -> **Retype**. Change `undefined4` to `char *` or `int`. The decompiler will re-structure the code (e.g., showing array access `ptr[i]` instead of pointer math `*(ptr + i*4)`).
* **Split Variables:** Sometimes the decompiler re-uses the same variable for two different things. Right-click -> **Split Variable** to force it to treat them separately.


### 15. The "Function ID" (Ghidra's FLIRT)

* Ghidra's version of library recognition.
* **Tools -> Function ID -> Attach existing FidDb**.
* Select libraries like `Visual Studio 2019`, `OpenSSL`, etc.
* Run the "Function ID" analyzer. It hashes functions and matches them against the database to name standard library calls.


### 16. Headless Analysis (Automation)

* You have 1,000 malware samples. You want to check if they contain the string "HACKED".
* Don't open GUI. Use `analyzeHeadless`.
* **Command:** `./analyzeHeadless /ProjectDir ProjectName -import malware.exe -postScript FindString.java`.
* This allows massive scaling of analysis without human interaction.

***

## Part VI: Anti-Reversing \& De-Obfuscation

### 17. Detecting Debuggers (The Basics)

* **IsDebuggerPresent:** Checks the PEB (Process Environment Block) byte at offset `0x2`.
    * **Bypass:** Patch the jump after the call (change `JZ` to `JNZ` or `NOP` it out). Or simpler: manually set the flag in the PEB to 0 using the debugger's memory view.
* **CheckRemoteDebuggerPresent:** Checks if the program is being debugged by another process.
* **NtGlobalFlag:** At `PEB + 0x68`, the value is usually 0. If debugged, it's `0x70`.


### 18. Timing Checks

* **RDTSC (Read Time-Stamp Counter):** Returns the number of CPU cycles since reset.
* **The Trick:** Malware reads `RDTSC`, runs some code, reads `RDTSC` again.
    * If `End - Start > 0x10000` cycles, it assumes a human is single-stepping in a debugger.
* **Bypass:**
    * **Patch:** NOP out the check.
    * **Dynamic:** In a VM, configure the hypervisor to exit on RDTSC instructions and fake the return value.


### 19. Stack Strings (Obfuscation)

* Malware hides strings by building them byte-by-byte on the stack to defeat `strings` util.
    * `MOV [EBP-4], 'H'`
    * `MOV [EBP-3], 'i'`
* **Analysis:**
    * **Ghidra Decompiler:** Often automatically recombines these into "Hi".
    * **Scripting:** Write a script that iterates instructions. If it sees a sequence of `MOV [Stack], Imm8`, collect the immediates and print the string.


### 20. Dead Code \& Opaque Predicates

* **Opaque Predicate:** A conditional jump that is *always* true (or always false), but the disassembler doesn't know it.
    * Example: `7y^2 - 1 != x^2` (Mathematical constants).
    * Example: `XOR EAX, EAX` followed by `JZ label` (Always jumps).
* **Goal:** To confuse the control flow graph (CFG).
* **Solution:** Use the decompiler! Decompilers perform "Dead Code Elimination" and will often remove the branch that is never taken, showing you the "real" control flow.

***

## Part VII: Scripting (The Force Multiplier)

### 21. When to Script?

* **Rule of Thumb:** If you have to do a task more than 3 times, script it.
* **Examples:**
    * Decrypting a block of strings XOR-encoded with `0x55`.
    * Renaming a list of functions based on a hash table found in the binary.
    * Finding all calls to `malloc` and checking the size parameter.


### 22. IDAPython (IDA) Essentials

* `idc.get_screen_ea()`: Get current cursor address.
* `idc.get_byte(addr)` / `idc.patch_byte(addr, val)`: Read/Write bytes.
* `idautils.Functions()`: Iterate all functions.
* `idc.set_name(addr, "Name")`: Rename something.
* **Snippet (XOR Decryptor):**

```python
start = 0x401000
length = 0x50
key = 0x55
for i in range(length):
    b = idc.get_byte(start + i)
    idc.patch_byte(start + i, b ^ key)
```


### 23. Ghidra Scripting (Java/Python)

* Ghidra's "FlatProgramAPI" makes scripting easy.
* `currentAddress`: Where the cursor is.
* `getFunctionContaining(address)`: Get the function object.
* `findBytes(start, "byte string")`: Search memory.
* **Snippet (XOR Decryptor in Python):**

```python
addr = currentAddress
key = 0x55
for i in range(10):
    b = getByte(addr.add(i))
    setByte(addr.add(i), b ^ key)
```


***

## Part VIII: Data Structures \& Memory Layout

### 24. Recognizing Linked Lists

* **Structure:** A node contains `Data` and `NextPointer`.
* **Asm Pattern:** `MOV EAX, [EAX+4]` inside a loop (where `+4` is the next pointer). The loop terminates when `EAX` is 0 (NULL).
* **Ghidra Tip:** Define a struct `Node`. Add a field `next` of type `Node *`. This creates a recursive type definition which Ghidra handles beautifully.


### 25. Recognizing Arrays vs Structs

* **Arrays:**
    * Accessed via a calculated index: `Base + Index * ElementSize`.
    * Code uses a loop variable (e.g., `ESI`) scaled by 4 or 8.
* **Structs:**
    * Accessed via hardcoded offsets: `Base + 0x4`, `Base + 0x10`.
    * Usually different types (int, then char*, then byte).


### 26. Global vs Stack vs Heap

* **Global (.data/.bss):** Addresses are fixed (e.g., `0x403000`). Lifetime is the entire program execution.
* **Stack:** Addresses are relative to `EBP` or `ESP` (e.g., `[EBP-8]`). Lifetime is only the current function.
    * **Tip:** If a function returns a pointer to a stack variable, that's a serious bug (Use-After-Return) or a vulnerability.
* **Heap:** Addresses come from `EAX` after a `malloc/new` call. Lifetime is manual (`free/delete`).

***

## Part IX: The "Human" Element

### 27. Commenting Strategy

* **Anterior Comments (Line Above):** Use for section headers or explaining a block.
* **Posterior Comments (End of Line):** Use for explaining a specific tricky instruction.
* **Repeatable Comments (IDA `;` vs `:`):**
    * Use `;` (Repeatable) for global variables. The comment will appear *everywhere* that variable is used.
    * Use `:` (Non-repeatable) for local context (e.g., "Loop counter"). You don't want "Loop counter" showing up in other functions that happen to use the same register.


### 28. "Stuck" Protocol

* When you hit a wall (and you will):

1. **Change View:** Switch from Decompiler to Graph View.
2. **Change Scope:** Zoom out. Look at the caller. Who calls this function? Why?
3. **Change Data:** Look at the data references. What global variables are touched?
4. **Dynamic:** Fire up the debugger. Run it. See what the values *actually* are. Static analysis is theoretical; dynamic is factual.


### 29. Search Strategies

* **Constant Search:** Found a crypto constant? Search for it.
* **String Search:** Found a unique error? Search for it.
* **Sequence of Bytes:** Found a distinct opcode pattern (like a specific prologue)? Search for it to find similar functions.
* **Immediate Value:** Search for specific integers (e.g., `0x1000` buffer size) to find all places that allocate that specific size.


### 30. Documentation

* **Keep a Lab Notebook:**
    * Write down offsets of interest.
    * Write down hypotheses ("I think this function parses the config").
    * Write down verified facts ("Confirmed: Arg1 is the file path").
* Reversing is a memory game. You will forget what `sub_401000` did in 2 hours. Write it down or rename it immediately.

***

# Summary Checklist for Every Binary

1. **File Command:** What is it? (PE/ELF, 32/64, x86/ARM)
2. **Strings:** Strings -> file.txt. Read it.
3. **Imports:** What APIs does it use?
4. **Packer Check:** High entropy? Run UnpacMe or manual unpack.
5. **Load in IDA/Ghidra:**
    * Auto-analyze.
    * Apply Signatures (FLIRT/FidDb).
    * Run "Strings" setup.
6. **Entry Point Analysis:** Is it main? Or a wrapper (CRT startup)? Find real main.
7. **Identify Key Structures:** Find `malloc`/`new`. See how data is stored.
8. **Rename, Type, Comment:** Iterate until the logic is clear.


[^1]: https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/85c79ace-8eda-4ca0-8a45-1ab60feb41af/Reverse-Engineering-for-Beginners-Dennis-Yurichev-2023-xdvipdfmx-20210609-8bc00d46d25a6af950eb2f8854a0a8e7-Annas-Archive.pdf

[^2]: https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/4f7e4bf2-71d7-44f7-94b0-f99997efe6e2/reversing_c.pdf

[^3]: https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/b84da16d-11b0-44fb-bff9-d34a0d5cd909/The-BOOK-of...-Chris-Eagle-The-IDA-pro-book_-the-unofficial-guide-to-the-world-s-most-popular-disassembler-2008-No-Starch-Press-libgen.li.pdf

[^4]: https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/96616222/ca55e207-8a74-49bf-85a7-2a125756c940/The-BOOK-of...-Chris-Eagle-Kara-Nance-The-Ghidra-Book_-The-Definitive-Guide-2020-No-Starch-Press-libgen.li.pdf

