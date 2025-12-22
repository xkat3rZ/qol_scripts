import gdb

# --- Modular Core Logic ---

class BaseBreakCommand(gdb.Command):
    """
    Base class for setting breakpoints relative to the PIE base address.
    Subclasses should implement `calculate_target(base_addr, user_input)`.
    """

    def __init__(self, name):
        super(BaseBreakCommand, self).__init__(name, gdb.COMMAND_USER)
        self.cmd_name = name

    def invoke(self, arg, from_tty):
        # 1. Parse argument
        argv = gdb.string_to_argv(arg)
        if len(argv) == 0:
            print(f"Usage: {self.cmd_name} <address_or_offset>")
            return
        
        try:
            user_input = int(argv[0], 0)
        except ValueError:
            print(f"Error: Invalid address '{argv[0]}'.")
            return

        # 2. Get Runtime Base Address
        base_addr = self._get_base_address()
        if base_addr is None:
            print("Error: Process is not running (starti first) or mapping not found.")
            return

        # 3. Calculate Final Address using the subclass's logic
        target_addr = self.calculate_target(base_addr, user_input)

        # 4. Set Breakpoint
        print(f"[{self.cmd_name}] Base: {hex(base_addr)} | Input: {hex(user_input)}")
        print(f"[{self.cmd_name}] Breaking at: {hex(target_addr)}")
        gdb.execute(f"break *{hex(target_addr)}")

    def calculate_target(self, base_addr, user_input):
        """Override this in subclasses."""
        raise NotImplementedError

    def _get_base_address(self):
        """Helper to find the runtime base address of the main binary."""
        try:
            if gdb.selected_inferior().pid <= 0:
                return None
            
            prog_space = gdb.current_progspace()
            if not prog_space or not prog_space.filename:
                return None
                
            bin_name = prog_space.filename.split('/')[-1]
            mappings = gdb.execute("info proc mappings", to_string=True)

            for line in mappings.splitlines():
                if bin_name in line:
                    parts = line.split()
                    try:
                        # Linux /proc/map format: Start End Size Offset ...
                        start_addr = int(parts[0], 16)
                        offset_str = parts[3]
                        # We want the mapping where the file offset is 0
                        if offset_str in ("0x0", "0"):
                            return start_addr
                    except (ValueError, IndexError):
                        continue
            return None
        except gdb.error:
            return None

# --- Command 1: gb (Offset Break) ---
# Usage: gb 0x1234  -> Breaks at Base + 0x1234

class OffsetBreak(BaseBreakCommand):
    def __init__(self):
        super(OffsetBreak, self).__init__("gb")

    def calculate_target(self, base_addr, offset):
        return base_addr + offset

# --- Command 2: gbg (Ghidra Break) ---
# Usage: gbg 0x101234 -> Breaks at Base + 0x101234 - 0x100000

class GhidraBreak(BaseBreakCommand):
    # Standard Ghidra base for PIE binaries is 0x100000. 
    # Change this if your binary has a different image base.
    GHIDRA_BASE = 0x100000

    def __init__(self):
        super(GhidraBreak, self).__init__("gbg")

    def calculate_target(self, base_addr, ghidra_addr):
        # Formula: Runtime_Addr = Base + (Ghidra_Addr - Ghidra_Base)
        return base_addr + (ghidra_addr - self.GHIDRA_BASE)

# --- Registration ---
OffsetBreak()
GhidraBreak()
