# 5 - Sealed Orders

## Challenge

<p align="center">
  <img src="asset/challenge.png" width="700" alt="5 - Sealed Orders Challenge">
</p>

## Challenge Banner

After connecting to the challenge server, the following banner is displayed:

```text
BINTULU MLNG - SEALED ORDERS :: SIS Controller Interface
Classification: CONFIDENTIAL - XENOTIME Investigation
Source: Compromised Safety Instrumented System, Train 9

Two-layer RSA envelope protects the sealed orders.

Layer 1 (outer seal): c1 = PREFIX^e1 mod n1
Layer 2 (inner order): c2 = (PREFIX * 2^1024 + FLAG)^e2 mod n2
```

The banner provides the RSA parameters required to solve the challenge.

### Layer 1 — Outer Seal

```python
n1 = 0x5cb077da0259c98d6ba22decf86ba868805fcf123e5c2912768a67a5de5a47b9844e27fc1d8e6c031c846466db755991d42a4109b9a1983c8683fd47b8651b2784c6d12928c75ab79ade613b6e31a5e083d516144e330403301b2a3836c05e4aa3ce3c5e672da6cdb6dfde3c10d99be5ffd7581f3adc90315ffe0dee176b674b

e1 = 65537

c1 = 0x14863ead80be77135eaf015e6d9695bc8c68a1caebcfc346c2885adeea363cab2b5a0c83ae1653bdd2b4828d5e1fa925255da2ba2e08bf80d59e04c0f4ba208875211e6fe36279372581aa97aed401253e91b1aeda9aeb9c798a7898b0c4167be4e2bd371f5ea75f9364a2183cd71274a0f41e0f02d23ee60116f768168a8957
```

### Layer 2 — Inner Order

```python
n2 = 0xc1aa1d2ab4dd487e0adae860e49f38fb8d29ff9c6a82ce7c9b680cf2b5d414c7679d49230ee4b56ac4c79f18ec53fc436801b83e4848f738f6ec842f5ca3fd22b78bd98abcdfc03c439e24672e1ea8d231c982ea5fa5c9031432c0b1c3692ffcaf6535530589d18ed4881ea013a070bdf740f5c426411cec58f55b9902d02a6514b897acefdd2d043980b01965cd983da7a9d1b20c391188cc36924731eeab059900360980a6b14cb4d0811fb9b2c835846ddba9c51372e4e90fa44866416744ed0c34b39cf55dd21dd9e8446c17aeaaacfec8088ce229ed694c7ff77c28e3b4db63c9573e6a43377a3b848ab43c933e9f0d0bbeaba640c272563d761d67af5ee4beac68183f775ef31ac02365f3068a156282a5dd9e04b63a5340de8ccc4b30d5507a2e8e966b7daede0a501a09b2323a64a11bd1619febc06e761bc72e476df7e6af25fcd1f4e976a4b6c736b6ec8585f9c669e4c162f44a5065c5c5b19efe9a9b5d9e15b0c46df3d21cba84dce67c4d243c0a264dabceed9325010d1317e9

e2 = 3

c2 = 0xbb8b1961dbc254e44e39ca39e7b3ea46f794c6b358277b66e63796b1e4354b9e0d6e0fb85e5a0019b91dd4e0ec455f872e2f698a0ce7298b90d10f6f702ad956b4f80fa41e2480d4d3ec73ed89aa548db5f17fcb12a165f8081e8102bffa7c95b2be7db5a3d05f5ee15f6ebbac99cbd5e6e6390cb8ea820c16a529a2807f1bde4e2bb5e043f37674473afdda4297261f0660490d5b9b6daac5dfb302c85c7a1b622b4fba579864365b8dd985e85d4916d0e181f02e1ceeff61b060976cbca8ac1cefcb05590f7c1b626338c912c565e168a45e1f0e866e343de49c0ba630172cbfac44089d9a4410806db0df33dd68f2f769c03ecbec821be50ffc9204a83fa47eb1ad3fe8ec7d384323c5f05e3556d2d4a7907b5c1a8f5f08f589da65c5e6a6b4014ec3cd6c9f866aff76b5b7d158ab3def189d6703c30a847fdfda2d696a86abf23c43d39adf0f5588c25ab0be2ebe4c498631698c60f7766aaaa925a2705f0bd517c01906313669bf86de34ea53eb354504225e8b0903b0d4c0d046243eff
```

The banner also specifies:

```python
L = 1024
```

### Available Commands

The server provides three commands:

| Command | Description |
|---|---|
| `lsb <hex>` | Returns the least significant bit of `decrypt(hex) mod n1` |
| `help` | Displays the challenge banner |
| `quit` | Closes the connection |

The oracle quota is:

```text
3000 queries per session
```

The most important command is `lsb`. It acts as an oracle by revealing whether the decrypted value is even or odd.

After recovering the first encryption layer, the `PREFIX` value is:

```python
PREFIX = 0xe03f1d269a31105da5ae5a154c00828a16a93329db8d60fb2bc5e6a58ba22fd4
```

## Solution

### 1. Connect to the challenge

The challenge provides a TCP service. We can connect to it using Netcat:

```bash
nc 165.245.185.210 5101
```

After connecting, the server displays the challenge banner.

The important information is:

- The challenge uses two layers of RSA encryption.
- The first layer protects a secret value called `PREFIX`.
- The second layer uses `PREFIX` together with the flag.
- The server provides an `lsb` command that reveals the least significant bit of an RSA decryption.
- We are allowed 3000 oracle queries per session.

### 2. Understand the RSA LSB oracle

RSA encryption follows this formula:

```text
c = m^e mod n
```

Where:

- `m` is the original message.
- `c` is the encrypted message.
- `e` is the public exponent.
- `n` is the RSA modulus.

Normally, recovering the original message from the ciphertext is difficult without the private key.

However, this challenge gives us an oracle that reveals one bit of information about a decrypted value:

```text
0 = even
1 = odd
```

This is known as an **LSB oracle attack**.

The useful property of RSA is that it is multiplicative. By multiplying the original ciphertext by carefully chosen values, we can make the decrypted result reveal information about the original plaintext.

For this challenge, we repeatedly multiply the ciphertext by powers of 2 and query the oracle.

The challenge provides:

```text
e1 = 65537
L  = 1024
```

We use 1024 oracle queries to recover enough information to reconstruct `PREFIX`.

### 3. Recover the PREFIX

Instead of manually sending hundreds of commands through Netcat, we can automate the attack using Python.

The script performs these operations:

1. Connects to the challenge server.
2. Reads the server banner.
3. Sends the modified ciphertext to the `lsb` command.
4. Collects the returned bits.
5. Reconstructs the original `PREFIX`.
6. Verifies the result by encrypting it again.

The verification is important. If this condition is true:

```python
pow(PREFIX, e1, n1) == c1
```

then the recovered value correctly matches the original ciphertext.

The recovered `PREFIX` is:

```python
PREFIX = 0xe03f1d269a31105da5ae5a154c00828a16a93329db8d60fb2bc5e6a58ba22fd4
```

We have now broken the first layer of encryption.

### 4. Understand the second RSA layer

The server also provides another RSA encryption formula:

```text
c2 = (PREFIX * 2^1024 + FLAG)^3 mod n2
```

The important values are:

```text
e2 = 3
L  = 1024
```

We already know `PREFIX`, so we can calculate the known part of the plaintext:

```python
const = PREFIX * (1 << 1024)
```

This means the encrypted message is:

```text
const + FLAG
```

The remaining task is to recover the flag.

A direct cube root of `c2` will not work because the original plaintext was raised to the power of 3 and reduced modulo `n2`.

The intended approach involves Coppersmith's method, which can recover small unknown values from certain modular equations.

However, we can use a simpler mathematical shortcut for this challenge.

### 5. Recover the flag using an algebraic shortcut

We know:

```text
c2 = (const + FLAG)^3 mod n2
```

The expression can be expanded using the binomial theorem:

```text
(const + FLAG)^3
= const^3
+ 3 * const^2 * FLAG
+ 3 * const * FLAG^2
+ FLAG^3
```

Because the result is reduced modulo `n2`, there is an unknown integer `k` such that:

```text
(const + FLAG)^3 = c2 + k * n2
```

We can estimate `k` using:

```python
k_approx = (const**3 - c2) // n2
```

For this challenge, the correction caused by the flag-related terms is small compared with `n2`.

As a result, the correct value of `k` can be found by trying nearby integers.

We then calculate:

```python
candidate = c2 + k * n2
```

If `candidate` is a perfect cube, its integer cube root gives us:

```text
const + FLAG
```

We simply subtract `const` to recover the flag as an integer.

The script uses an integer cube-root function to check each candidate. It does not use floating-point arithmetic, which is important when working with numbers this large.

For the actual challenge, the correct candidate is found at:

```text
delta = 1
```

This means we successfully recover the flag without needing to run Coppersmith's method.

### 6. Convert the recovered number into the flag

After recovering the flag as an integer, we convert it into bytes:

```python
byte_count = (FLAG.bit_length() + 7) // 8
flag_bytes = FLAG.to_bytes(byte_count, 'big')
```

We then search the resulting bytes for the expected flag format:

```python
import re

match = re.search(rb'PETRONAS\{[^}]+\}', flag_bytes)

if match:
    print(match.group(0).decode())
```

The recovered flag is:

```text
PETRONAS{b1ntulu_s34l3d_0rd3rs_c0pp3rsm1th}
```

### 7. What we learned

This challenge involved two separate RSA weaknesses.

**First layer: LSB oracle attack**

The server revealed whether the decrypted ciphertext was even or odd. By repeatedly modifying the ciphertext and collecting the returned bits, we recovered the original `PREFIX`.

**Second layer: Small unknown value**

The second RSA layer used a public exponent of 3 and included a known part of the plaintext. Instead of implementing the more complicated Coppersmith attack, we used the relationship between the known plaintext, the modulus, and the small flag value to recover the original integer.

The main lessons are:

- Read the challenge banner carefully. It contains important information about the encryption and available oracle.
- Recognize when a service exposes an oracle that leaks information about decrypted data.
- Automate repeated oracle queries with Python.
- Verify recovered RSA plaintext by encrypting it again.
- Check the sizes of the numbers before choosing an attack.
- Try simpler mathematical approaches before implementing more complicated techniques such as Coppersmith's method.

## Flag

```text
PETRONAS{b1ntulu_s34l3d_0rd3rs_c0pp3rsm1th}
```