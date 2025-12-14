# =============================================================================
# script_name: find_format_vulns.py
# description: Detects Unsafe Format String Vulnerabilities within a HARDCODED Memory Range
# category: Vulnerability Analysis
# =============================================================================
import pyghidra

try:
    from ghidra.ghidra_builtins import *
except:
    pass
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import PcodeOp
from java.awt import Color

# -----------------------------------------------------------------------------
# USER CONFIGURATION (EDIT THESE VALUES)
# -----------------------------------------------------------------------------
# Define your scan range here as hex strings (e.g., "0x00400000")
START_ADDR_STR = "0x100000"
END_ADDR_STR = "0x104047"

TARGETS = {
    "printf": 0,
    "fprintf": 1,
    "sprintf": 1,
    "snprintf": 2,
    "vprintf": 0,
    "vfprintf": 1,
    "vsprintf": 1,
    "vsnprintf": 2,
    "dprintf": 1,
    "syslog": 1,
}


# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------
def get_called_func_name(pcode_op):
    inputs = pcode_op.getInputs()
    if not inputs: return None
    addr_varnode = inputs[0]
    if addr_varnode.isAddress():
        func = getFunctionAt(addr_varnode.getAddress())
        if func: return func.getName()
    return None


def trace_to_address(varnode, depth=0):
    if depth > 5 or varnode is None: return None
    if varnode.isConstant(): return toAddr(varnode.getOffset())
    if varnode.isAddress(): return varnode.getAddress()

    def_op = varnode.getDef()
    if def_op is None: return None

    opcode = def_op.getOpcode()
    inputs = def_op.getInputs()

    if opcode == PcodeOp.CAST or opcode == PcodeOp.COPY:
        return trace_to_address(inputs[0], depth + 1)
    if opcode == PcodeOp.PTRSUB:
        if len(inputs) > 1 and inputs[1].isConstant():
            return toAddr(inputs[1].getOffset())
        if len(inputs) > 0:
            return trace_to_address(inputs[0], depth + 1)
    return None


def is_safe_format_string(varnode):
    target_addr = trace_to_address(varnode)
    if target_addr is None: return False
    mem = currentProgram.getMemory()
    block = mem.getBlock(target_addr)
    if block is None: return False
    if block.isInitialized(): return True
    return False


def analyze_function(func, monitor, decompiler):
    res = decompiler.decompileFunction(func, 120, monitor)
    if not res.decompileCompleted(): return
    high_func = res.getHighFunction()
    if high_func is None: return

    op_iter = high_func.getPcodeOps()
    while op_iter.hasNext():
        op = op_iter.next()
        if op.getOpcode() == PcodeOp.CALL:
            called_name = get_called_func_name(op)
            if called_name in TARGETS:
                fmt_idx = TARGETS[called_name]
                pcode_arg_idx = fmt_idx + 1
                inputs = op.getInputs()

                if pcode_arg_idx < len(inputs):
                    arg_varnode = inputs[pcode_arg_idx]

                    if not is_safe_format_string(arg_varnode):
                        addr = op.getSeqnum().getTarget()
                        print("[!] UNSAFE: {} at address {} at function {}".format(
                            called_name, addr, func.getName()))
                        createBookmark(addr, "VulnDetection", "Unsafe {} Usage".format(called_name))
                        setBackgroundColor(addr, Color(255, 200, 200))


# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------
def run():
    print("Initializing Static Range Scan...")

    # 1. Parse Static Addresses
    try:
        # getAddressFactory is the safe way to turn string "0x..." into an Address object
        addr_factory = currentProgram.getAddressFactory()

        start_addr = addr_factory.getAddress(START_ADDR_STR)
        end_addr = addr_factory.getAddress(END_ADDR_STR)

        if start_addr is None or end_addr is None:
            print("[-] Error: Could not parse one of the addresses. Check formatting.")
            return

    except Exception as e:
        print("[-] Error parsing addresses: " + str(e))
        return

    # Basic Validation
    if start_addr >= end_addr:
        print("[-] Invalid Range: START ({}) >= END ({})".format(start_addr, end_addr))
        return

    print("[*] Target Range: {} to {}".format(start_addr, end_addr))

    # Initialize Decompiler
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()

    # Get all functions
    func_manager = currentProgram.getFunctionManager()
    func_iter = func_manager.getFunctions(True)

    analyzed_count = 0
    skipped_count = 0

    for func in func_iter:
        func_entry = func.getEntryPoint()

        # 2. Check if Function Entry Point is Inside Range
        if func_entry >= start_addr and func_entry <= end_addr:
            if not func.isThunk() and not func.isExternal():
                analyze_function(func, monitor, decompiler)
                analyzed_count += 1
            else:
                skipped_count += 1

    print("Scan Complete.")
    print("Functions Analyzed: {}".format(analyzed_count))
    decompiler.dispose()


if __name__ == "__main__":
    run()
