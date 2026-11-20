# Boot Survivor [2.8]

## Challenge

<p align="center">
  <img src="asset/challenge.png" width="700" alt="Boot Survivor [2.8] Challenge">
</p>

## Solution

This writeup assumes you are new to CTFs and digital forensics. We will walk through how to find malware that survives a system reboot (Persistence), specifically by looking at Windows Registry Run Keys.

### 1. Challenge Overview

The challenge description gives us the core hint:
> *"The workstation was rebooted twice during the investigation window. Whatever was running came back every time. Something is anchored deep enough to survive a restart."*

**Breakdown of the clues:**
*   **"Came back every time" / "Survive a restart"**: In incident response, this is called **Persistence**. The attacker has set up a mechanism that tells Windows, "Hey, run my malware every time the computer turns on."
*   **"Anchored deep enough"**: While Scheduled Tasks are one way to do this, the oldest and most common trick in the book is modifying the **Windows Registry**. Specifically, the `Run` keys.

When a user logs into Windows, the OS checks specific Registry keys and automatically executes whatever programs are listed there. 

### 2. Step 1 — Finding the Persistence

First, ensure you are in the extracted VM directory:
```bash
cd ~/Downloads/PETCTF2026PrelimWriteup/Kerteh/1\ -\ Infected\ Package/extracted_vm
```

The Registry is stored in binary hive files inside `C:\Windows\System32\config\`. The `Run` keys for the local machine are located in the `SOFTWARE` hive.

Because these are binary files, we can't just `cat` them. But we can use `grep` or `strings` to search for known keywords like "PETRONAS" or "svchost".

Let's search the `SOFTWARE` hive:
```bash
strings Windows/System32/config/SOFTWARE | grep -i "PETRONAS"
```
*(If that returns nothing, try `grep -a "PETRONAS" Windows/System32/config/SOFTWARE`)*

**Output:**
```text
C:\ProgramData\Triconex\svchost.exe -k PETRONAS{R3G_P3RS1ST3NC3_K3Y} -silent
```

### 3. Step 2 — Analyzing the Malware

We found the hidden command! The attacker added a Registry Run Key that points to a fake `svchost.exe` placed in the `Triconex` folder.

Let's look at that file to confirm:
```bash
ls -la ProgramData/Triconex/
file ProgramData/Triconex/svchost.exe
```

It is a malicious binary masquerading as a legitimate Windows service (`svchost.exe`). Every time Windows boots, it reads the Registry, sees this fake `svchost.exe`, and runs it with the arguments `-k PETRONAS{R3G_P3RS1ST3NC3_K3Y} -silent`.

The flag is hidden right there in the execution arguments.

### 4. The Flag

**`PETRONAS{R3G_P3RS1ST3NC3_K3Y}`**

### 5. Cheat Sheet — Commands Used

```bash
# 1. Navigate to the extracted VM
cd ~/Downloads/PETCTF2026PrelimWriteup/Kerteh/1\ -\ Infected\ Package/extracted_vm

# 2. Search the Registry SOFTWARE hive for the flag
strings Windows/System32/config/SOFTWARE | grep -i "PETRONAS"

# 3. (Optional) Look at the dropped malware
ls -la ProgramData/Triconex/
```

## Flag

```text
PETRONAS{R3G_P3RS1ST3NC3_K3Y}
```
