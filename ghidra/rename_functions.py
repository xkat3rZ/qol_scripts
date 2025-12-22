# Rename functions based on MULTIPLE logging configurations (by Address) with Format String Filter
#
# This script automates the renaming of functions in a Ghidra project by analyzing calls to specific logging functions.
# It works by:
# 1. Finding all places where a logging function is called.
# 2. Decompiling the caller function to inspect the arguments passed to the log.
# 3. Filtering those calls based on a format string argument (e.g., must start with "LOG:").
# 4. Extracting a function name string from another argument in that same call.
# 5. Renaming the caller function using that extracted string.
#
# @author x (Modified based on RD Team of Conviso)

import pyghidra

try:
    from ghidra.ghidra_builtins import *
except:
    pass

# Import necessary Ghidra API classes
import ghidra.app.script.GhidraScript as GhidraScript
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import Address
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# --- Python 2/3 Compatibility Fix ---
# Ghidra 9.x/10.x uses Jython (Python 2.7), while newer setups or Ghidrathon use Python 3.
# 'basestring' exists in Py2 but not Py3. This ensures the script runs in both environments.
try:
    basestring
except NameError:
    basestring = str
# ------------------------------------

# --- Global Ghidra State Setup ---
current_program = getCurrentProgram()  # The binary currently loaded in the tool
monitor = ConsoleTaskMonitor()  # Prints progress/errors to the Ghidra console window
options = DecompileOptions()  # Default decompiler settings
ifc = DecompInterface()  # The interface used to programmatically decompile functions

ifc.setOptions(options)
ifc.openProgram(current_program)  # Attach decompiler to the current binary


def get_target_function_from_addr(address_int):
    """
    Converts a raw integer address (e.g., 0x08048000) into a Ghidra Function object.
    Returns None if the address is invalid or no function is defined there.
    """
    target_addr = toAddr(address_int)
    if target_addr is None:
        print("ERROR: Address {} is invalid.".format(hex(address_int)))
        return None

    func = getFunctionAt(target_addr)
    if func is None:
        print("ERROR: No function found at address {}.".format(hex(address_int)))
        return None

    return func


def get_callers(function):
    """
    Finds all functions that call the specific 'function' object.
    It looks at cross-references (XREFs) to the function's entry point.
    """
    address = function.getEntryPoint()
    callers = set()

    # getReferencesTo returns all references (calls, jumps, data pointers)
    # refs = getReferencesTo(address) # only gives 4096 references max

    refManager = current_program.getReferenceManager()
    refIterator = refManager.getReferencesTo(address)

    while refIterator.hasNext():
        ref = refIterator.next()
        # We only care about code execution flows (CALL instructions)
        if ref.getReferenceType().isCall():
            # Find which function contains the instruction making the call
            caller = getFunctionContaining(ref.getFromAddress())
            if caller is None: continue
            callers.add(caller)

    return list(callers)


def get_string_content(obj):
    """
    Helper to extract the actual string text from various Ghidra objects.

    When we resolve an argument, we might get:
    1. A raw Address (the pointer to the string).
    2. A Data object (Ghidra's representation of defined data at an address).

    This function handles both and reads the ASCII string from memory.
    """
    addr_to_read = None

    # If the object is already a python string, just return it.
    if isinstance(obj, basestring):
        return obj

    # If it is a Ghidra Address object, we will read from there.
    if isinstance(obj, Address):
        addr_to_read = obj

    # If it is a Ghidra Data object, get the address where the data is located.
    elif hasattr(obj, "getAddress"):
        addr_to_read = obj.getAddress()

    if addr_to_read:
        try:
            # getMemory().getString() reads a null-terminated ASCII string from the address.
            return current_program.getMemory().getString(addr_to_read)
        except:
            return None

    return None


def resolve_args(args):
    """
    Converts raw Varnodes (low-level variables from the decompiler) into usable values.

    The decompiler represents function arguments as 'Varnodes'. These can be:
    - Constants (immediate values).
    - Unique/Temporary variables (intermediate values calculated by the decompiler).
    - High-level variables (named variables).
    """
    resolveds = []
    for arg in args:
        if arg.isConstant():
            # It's a direct number (e.g., 0x4000). Usually a pointer address.
            resolved = arg.getOffset()
        elif arg.isUnique():
            # It's a temporary variable. We trace it back to its definition.
            # This handles cases like:
            #   tmp = 0x4000;
            #   log(tmp);
            the_def = arg.getDef()
            if the_def and the_def.getNumInputs() > 0:
                constant_offset = the_def.getInput(0).getOffset()
                constant_addr = toAddr(constant_offset)

                # Check if Ghidra has 'Data' defined at this address (e.g., a known string)
                data = getDataContaining(constant_addr)
                if data:
                    resolved = data.getValue()
                else:
                    # If no data is defined, just return the address so we can read raw memory later.
                    resolved = constant_addr
            else:
                resolved = None
        else:
            # It's a high-level variable. We try to get its name.
            high = arg.getHigh()
            resolved = high.getName() if high else None
        resolveds.append(resolved)
    return resolveds


def get_calls_from_all_callers(callers, callee):
    """
    Iterates over every function that calls our logging function ('callee')
    and extracts the arguments passed in every single call site.
    """
    callers_info = []
    for caller in callers:
        caller_info = {
            'caller': {
                'name': caller.getName(),
                'address': caller.getEntryPoint()
            },
            'calls': get_calls_from_caller(caller, callee)
        }
        callers_info.append(caller_info)
    return callers_info


def get_calls_from_caller(caller, callee):
    """
    Decompiles a specific 'caller' function to find the exact P-Code operations
    where 'callee' (the logging function) is invoked.
    """
    calls = []

    # Decompile the function with a 60-second timeout
    res = ifc.decompileFunction(caller, 120, monitor)
    high_func = res.getHighFunction()

    if high_func:
        # Iterate over all P-Code operations (low-level instructions)
        opiter = high_func.getPcodeOps()
        while opiter.hasNext():
            op = opiter.next()
            mnemonic = str(op.getMnemonic())

            # We only care about CALL instructions
            if mnemonic == "CALL":
                inputs = op.getInputs()

                # Input 0 is the address of the function being called
                if len(inputs) > 0:
                    address = inputs[0].getAddress()

                    # Inputs 1 through N are the arguments passed to the function
                    args = inputs[1:]

                    # Check if this CALL is targeting our logging function
                    if address == callee.getEntryPoint():
                        location = op.getSeqnum().getTarget()
                        call_info = {
                            'location': location,
                            'callee': {
                                'name': callee.getName(),
                                'address': callee.getEntryPoint()
                            },
                            # Resolve the arguments from Varnodes to readable values
                            'args': resolve_args(args)
                        }
                        calls.append(call_info)
    return calls


def get_real_name_candidates(callers_info, name_arg_num, fmt_arg_num, fmt_prefix):
    """
    Filters the extracted calls.
    1. Checks if the argument at 'fmt_arg_num' starts with 'fmt_prefix'.
    2. If it matches, extracts the potential function name from 'name_arg_num'.
    """
    callers_candidates = []
    for info in callers_info:
        names_candidates = set()
        caller_info = {'caller': info['caller']}

        for call in info['calls']:
            args = call['args']

            # --- FILTERING LOGIC ---
            # Ensure the call has enough arguments
            if fmt_arg_num < len(args):
                fmt_obj = args[fmt_arg_num]
                fmt_str = get_string_content(fmt_obj)

                # If format string is missing or doesn't match the prefix, SKIP this call
                if not fmt_str or not fmt_str.startswith(fmt_prefix):
                    continue
            else:
                continue

            # --- EXTRACTION LOGIC ---
            # If we passed the filter, try to get the function name argument
            if name_arg_num < len(args):
                candidate_obj = args[name_arg_num]
                candidate_name = get_string_content(candidate_obj)

                if candidate_name:
                    names_candidates.add(candidate_name)

        # Only add this caller to the list if we found at least one valid candidate name
        if names_candidates:
            caller_info['candidates'] = list(names_candidates)
            callers_candidates.append(caller_info)

    return callers_candidates


def rename_all(callers_candidates):
    """
    Applies the renaming.
    It checks for safety:
    - Only renames functions starting with "FUN_" (default Ghidra names).
    - Skips if multiple conflicting names were found for the same function.
    """
    total = len(callers_candidates)
    if total == 0:
        print("No callers matched criteria.")
        return

    count = 0
    for callers_candidate in callers_candidates:
        current_name = callers_candidate['caller']['name']
        candidates = callers_candidate['candidates']

        # Safety: Don't overwrite manually named functions (only FUN_...)
        if not current_name.startswith('FUN_'):
            continue

        # Ambiguity check: Did we find two different log calls with different names?
        if len(candidates) != 1:
            msg = "ERROR   - {} - Ambiguous candidates: {}"
            print(msg.format(current_name, str(candidates)))
            continue

        function_obj = getFunction(current_name)
        new_name = str(candidates[0])

        # Sanitize the name (remove spaces, newlines, quotes)
        new_name = new_name.replace(" ", "_").replace("\n", "").replace("\r", "")
        new_name = new_name.replace('"', '')

        if not new_name:
            continue

        # Apply the new name to the function in the database
        function_obj.setName(new_name, SourceType.USER_DEFINED)
        print("SUCCESS - {} renamed to {}".format(current_name, new_name))
        count += 1

    perc = (float(count) / float(total)) * 100.0
    print("From {} matching functions {} were renamed - {:.2f}% ".format(total, count, perc))


def rename_from_logging_address(target_address, name_arg_index, fmt_arg_index, fmt_prefix):
    """
    Orchestrates the process for a single logging configuration.
    """
    print("Analyzing logging function at: {}".format(hex(target_address)))
    print("Filtering for format string at index {} starting with '{}'".format(fmt_arg_index, fmt_prefix))

    callee = get_target_function_from_addr(target_address)

    if callee:
        print("Found target function: {}".format(callee.getName()))
        callers = get_callers(callee)
        print("Found {} callers (total).".format(len(callers)))

        # --- DEBUG: Print all callers found to console ---
        # print("\n[DEBUG] List of all callers found:")
        # for caller in callers:
        #     print(" - {} @ {}".format(caller.getName(), caller.getEntryPoint()))
        # print("[DEBUG] End of caller list.\n")
        # --------------------------------

        # 1. Get arguments for every call
        callers_info = get_calls_from_all_callers(callers, callee)
        # 2. Filter calls by format string and extract names
        callers_candidates = get_real_name_candidates(callers_info, name_arg_index, fmt_arg_index, fmt_prefix)

        print("Found {} callers matching filter criteria.".format(len(callers_candidates)))
        # 3. Rename the functions
        rename_all(callers_candidates)
    else:
        print("Aborting.")


def main():
    # --- CONFIGURATION LIST ---
    # Add dictionaries here to define multiple logging patterns.
    # Each dictionary represents one "rule" for renaming.
    configs = [
        {
            'address': 0x101159,  # The address of the logging function in memory
            'fmt_index': 1,  # Argument index (0-based) where the format string is passed
            'fmt_prefix': "LOD",  # The string MUST start with this to trigger a rename
            'name_index': 2  # Argument index where the function name string is passed
        },
        {
            'address': 0x101208,
            'fmt_index': 2,
            'fmt_prefix': "LOG1",
            'name_index': 3
        },
    ]

    print("Starting Multi-Config Rename Script...\n")

    for i, config in enumerate(configs):
        print("--- Processing Configuration #{} ---".format(i + 1))
        rename_from_logging_address(
            config['address'],
            config['name_index'],
            config['fmt_index'],
            config['fmt_prefix']
        )
        print("\n")


if __name__ == '__main__':
    main()
