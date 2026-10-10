# REW-001 — keycheck name/serial crackme

| Field | Value |
| --- | --- |
| ID | REW-001 |
| Target | [`crackme/keycheck.c`](../crackme/keycheck.c) |
| Platform | Linux ELF x86-64 (also builds as PE with a MinGW or Zig toolchain) |
| Goal | Recover the serial algorithm and the success banner encoding |
| Tooling | `gcc 16`, `objdump`, `bintriage`, `crackme/keygen.py` |

## Build

```sh
gcc -O0 -fno-stack-protector -o keycheck crackme/keycheck.c
```

`-O0` keeps the FNV loop and the XOR decode obvious in the disassembly. Stack canaries are
disabled so that `__stack_chk_fail` does not clutter the import list; this is a teaching aid, not
a recommendation for production software.

## Surface behaviour

```text
$ ./keycheck
usage: ./keycheck <name> <serial>
$ ./keycheck alice 00000000
Access denied.
$ ./keycheck alice "$(python crackme/keygen.py alice)"
Access granted.
```

`strings` shows `Access denied.` and the usage line. It does not show `Access granted.`

## Triage

`bintriage` on a local build reports an ELF x64 PIE with NX enabled, partial RELRO, no canary
and no Fortify. Imports are limited to libc (`puts`, `fprintf`, `strlen` and friends). No
network, process or injection APIs appear. Section entropies are ordinary for an unstripped
`-O0` binary; nothing suggests packing.

## Serial algorithm

`main` hashes `argv[1]` with `fnv1a32`, parses `argv[2]` as eight hex digits, and compares the
two 32-bit values. The FNV-1a offset and prime are visible as immediates:

```text
0000000000001159 <fnv1a32>:
    1165:       c7 45 fc c5 9d 1c 81    movl   $0x811c9dc5,-0x4(%rbp)
    ...
    1187:       31 45 fc                xor    %eax,-0x4(%rbp)
    118d:       69 c0 93 01 00 01       imul   $0x1000193,%eax,%eax
```

`0x811c9dc5` is the standard FNV-1a 32-bit offset basis; `0x01000193` is the FNV prime. The
serial is therefore the lowercase eight-digit hex rendering of that hash. The companion script
[`crackme/keygen.py`](../crackme/keygen.py) implements the same function and is covered by the
test suite.

Addresses above come from one `gcc -O0` build on x86-64 Linux; a rebuild will shift them, but
the immediates and the symbol names stay stable.

## Success banner

`decode_success` walks a byte array labelled `SUCCESS_ENC` and XORs each byte with `0x37`:

```text
00000000000011aa <decode_success>:
    11c0:       48 8d 15 49 0e 00 00    lea    0xe49(%rip),%rdx        # 2010 <SUCCESS_ENC>
    ...
    11d1:       83 f0 37                xor    $0x37,%eax
```

Decoding the fifteen bytes at `SUCCESS_ENC` with key `0x37` yields `Access granted.`. The fail
path prints the cleartext `FAIL_MSG` instead.

## Recovery steps (summary)

1. Confirm the compare in `main` is between `fnv1a32(name)` and `parse_serial(serial)`.
2. Read the FNV offset and prime from the `fnv1a32` immediates (or from the source).
3. Implement the hash (see `keygen.py`) and emit eight lowercase hex digits.
4. Optionally recover the success string by XOR-decoding `SUCCESS_ENC` with `0x37`.

## Limitations

- This write-up describes a self-authored teaching binary. It is not a general method for
  defeating commercial licence checks.
- Disassembly excerpts are for a specific unoptimized ELF build. PE builds share the algorithm
  but not the addresses or the CRT.
- `bintriage` performs static analysis only; it does not unpack or rewrite the binary.
