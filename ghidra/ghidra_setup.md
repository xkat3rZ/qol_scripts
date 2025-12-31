## 1. Listing View Configuration
*All settings below are found in `Edit` -> `Tool Options` -> `Listing Fields`*

### Visual De-cluttering
*   **One line per instruction:**
    *   *Tab:* `Bytes Field`
    *   *Setting:* Set "Maximum lines to display" to **1**.
    *   *Setting:* Check "Display in Upper Case".
*   **Disable Horizontal Scrolling:**
    *   *Tab:* `Mouse`
    *   *Setting:* Uncheck "Enable Horizontal Scrolling" (forces text wrap or truncation).
*   **Clean Function Headers:**
    *   *Tab:* `Format Code`
    *   *Setting:* Check "Flag Function Entry" and "Flag Function Exits".
    *   *Tab:* `Labels Field`
    *   *Setting:* **Uncheck** "Display Function Label" (removes the redundant label line).

### Readability & Fonts
*   **Real Register Names:** (Stop Ghidra from replacing `EAX` with `local_var_1`)
    *   *Tab:* `Operands Field`
    *   *Setting:* **Uncheck** "Markup register variable references".
*   **Array Formatting:**
    *   *Tab:* `Array Options`
    *   *Setting:* Change "Array Index Format" to **hex**.
    *   *Setting:* Adjust "Elements per line" to compact the view.
*   **Listing Font:**
    *   *Menu:* `Edit` -> `Tool Options` -> `Listing Display`
    *   *Action:* Choose a monospaced font and high-contrast colors suitable for long sessions.

### Interaction & Highlighting
*   **Left-Click Highlighting:** (Critical for IDA users)
    *   *Tab:* `Cursor Text Highlight`
    *   *Setting:* Set "Mouse Button To Activate" to **LEFT** (Default is Middle).
*   **Cross-References (XREFs):**
    *   *Tab:* `XREFs Field`
    *   *Setting:* Increase the number of XREFs displayed to see more callers/callees at a glance.

## 2. Hex Editor & Structures
*   **Hex Editor Font:**
    *   *Menu:* `Edit` -> `Tool Options` -> `ByteViewer`
    *   *Action:* Select a legible monospaced font.
*   **Structure Offsets:**
    *   *Menu:* `Edit` -> `Tool Options` -> `Structure Editor`
    *   *Setting:* Enable **Hexadecimal offsets** (crucial for correlating with assembly).

## 3. Shortcuts (Key Bindings)
*The goal is to match IDA Pro standards.*
*   *Menu:* `Edit` -> `Tool Options` -> `Key Bindings`
*   *Recommended Mappings:*
    *   **C**: Define Code
    *   **D**: Define Data
    *   **X**: Show Cross-references (Xrefs)
    *   **Esc**: Go Back / Navigate Previous
    *   **U**: Undefine

## 4. Analysis Workflow
1.  **Import:** Use `File` -> `Import File`.
    *   *Note:* Ensure the "Language" (Processor/Endianness/Compiler) is correct if not auto-detected.
2.  **Auto-Analysis:** Allow the default analyzers to run on new files.
3.  **Manual Updates:**
    *   Use **Symbol Tree** to find exports/entry points.
    *   Use **Data Type Manager** to load external type libraries (Windows headers, etc.).

## 5. Pro Tip: Link Processor Manuals (HTTP vs FILE Fix)
*Ghidra normally looks for manuals via the configured protocol. A common issue prevents local PDFs from opening if the protocol defaults to `HTTP_URL`.*

1.  **Locate the Manuals Directory:**
    *   Navigate to: `Ghidra/Processors/<ProcessorName>/data/manuals/` (e.g., `.../x86/data/manuals/`).
2.  **Edit the Index File:**
    *   Open the `.idx` file (e.g., `x86.idx`) in a text editor.
3.  **Fix the Protocol:**
    *   Locate the manual definition header.
    *   Change the format property from `${HTTP_URL}` to `${FILE_URL}`.
    *   *Example:*
        ```
        @ Intel_SDM.pdf [Format=${FILE_URL}]
        ```
    *   *Note:* Without this change, Ghidra may attempt to treat the filename as a web link or fail to resolve the local path on some Linux/macOS systems.
4.  **Add the PDF:**
    *   Place your PDF (e.g., `Intel_SDM.pdf`) in the same `manuals` folder.
    *   Restart Ghidra to apply changes.


- references
[^1]: https://securelist.com/how-to-train-your-ghidra/108272/