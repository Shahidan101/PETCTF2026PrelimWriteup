# The Audit Trail [6.8]

## Challenge

<p align="center">
  <img src="asset/challenge.png" width="700" alt="The Audit Trail [6.8] Challenge">
</p>

## Solution

This writeup assumes you are new to CTFs and digital forensics. We will walk through how Windows Event Logs work, how to extract readable text from binary log files, and how to find evidence of execution left by an attacker.

### 1. Challenge Overview

The challenge description gives us a strong hint about where to look:
> *"Windows was watching. Even when the attacker thought they were operating in the shadows, the operating system quietly recorded exactly what was executed. The evidence is buried in the logs - if you know which ones."*

**Breakdown of the clues:**
*   **"Quietly recorded exactly what was executed"**: This points directly to **Windows Event Logs**. When processes run or scripts execute, Windows logs them. Specifically, PowerShell logs exact script blocks if Script Block Logging is enabled.
*   **"Buried in the logs"**: Windows stores these logs in `C:\Windows\System32\winevt\Logs\` as `.evtx` files.

### 2. Step 1 — The Encoding Trap

Windows Event Logs (`.evtx`) are binary XML files that store string data in **UTF-16LE** (16-bit little-endian). If you use standard tools like `strings` or `grep`, they will look for standard ASCII text and find nothing.

To properly read the text inside these logs, we must tell `strings` to look for 16-bit little-endian encoding using the `-e l` flag.

First, ensure you are in the extracted VM directory:
```bash
cd ~/Downloads/PETCTF2026PrelimWriteup/Kerteh/1\ -\ Infected\ Package/extracted_vm
```

Run the following command to search all the `.evtx` logs for the flag format:
```bash
strings -e l Windows/System32/winevt/Logs/*.evtx | grep -i "PETRONAS"
```

### 3. Step 2 — Analyzing the Output

The command will dump a massive amount of text, but if you look closely, you will see the author's PowerShell build script (which was logged by Windows) left comments revealing the flags for multiple challenges.

Look for the specific line matching this challenge's theme:
```text
# Flag: PETRONAS{SCR1PTB10CK_4UD1T}
$exfilKey = "PETRONAS{SCR1PTB10CK_4UD1T}"
```

The flag `SCR1PTB10CK_4UD1T` refers to **Script Block Auditing** (Event ID 4104). Even though the attacker ran the command to set `$exfilKey`, Windows silently recorded the entire code block in the logs, revealing the secret.

*(Bonus: You can also see the flags for the other challenges in this output, proving how powerful Event Log analysis can be!)*

### 4. The Flag

**`PETRONAS{SCR1PTB10CK_4UD1T}`**

### 5. Cheat Sheet — Commands Used

```bash
# 1. Navigate to the extracted VM
cd ~/Downloads/PETCTF2026PrelimWriteup/Kerteh/1\ -\ Infected\ Package/extracted_vm

# 2. Search Event Logs using UTF-16LE encoding
strings -e l Windows/System32/winevt/Logs/*.evtx | grep -i "PETRONAS"
```

## Flag

```text
PETRONAS{SCR1PTB10CK_4UD1T}
```
