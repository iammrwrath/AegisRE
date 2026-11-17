// ============================================================================
// AegisRE Studio — Embedded x86_64 Disassembler, Decompiler & Binary Engine
// Plus Ghidra Headless Decompiler Integration
// ============================================================================

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');

//Expanded Windows API Dictionary (Plain English + Categories + Signatures)
const API_DICTIONARY = {
  // Files & Storage
  CreateFileW: { category: 'Files & Folders', plain: 'Opens or creates a file or device on disk', sig: 'HANDLE CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, ...)' },
  CreateFileA: { category: 'Files & Folders', plain: 'Opens or creates a file or device on disk', sig: 'HANDLE CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, ...)' },
  ReadFile: { category: 'Files & Folders', plain: 'Reads raw bytes from an open file handle', sig: 'BOOL ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, ...)' },
  WriteFile: { category: 'Files & Folders', plain: 'Writes raw bytes to an open file handle', sig: 'BOOL WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, ...)' },
  DeleteFileW: { category: 'Files & Folders', plain: 'Deletes a file from the filesystem', sig: 'BOOL DeleteFileW(LPCWSTR lpFileName)' },
  DeleteFileA: { category: 'Files & Folders', plain: 'Deletes a file from the filesystem', sig: 'BOOL DeleteFileA(LPCSTR lpFileName)' },
  CopyFileW: { category: 'Files & Folders', plain: 'Copies a file to a new path', sig: 'BOOL CopyFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, BOOL bFailIfExists)' },
  MoveFileExW: { category: 'Files & Folders', plain: 'Moves or renames a file or directory', sig: 'BOOL MoveFileExW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, DWORD dwFlags)' },
  FindFirstFileW: { category: 'Files & Folders', plain: 'Scans a directory for matching files', sig: 'HANDLE FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData)' },
  FindNextFileW: { category: 'Files & Folders', plain: 'Continues scanning a directory for files', sig: 'BOOL FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData)' },
  GetFileAttributesW: { category: 'Files & Folders', plain: 'Checks if a file or folder exists and reads its attributes', sig: 'DWORD GetFileAttributesW(LPCWSTR lpFileName)' },
  GetTempPathW: { category: 'Files & Folders', plain: 'Retrieves the path to the Windows Temp directory', sig: 'DWORD GetTempPathW(DWORD nBufferLength, LPWSTR lpBuffer)' },
  SetFilePointerEx: { category: 'Files & Folders', plain: 'Moves the read/write position inside an open file', sig: 'BOOL SetFilePointerEx(HANDLE hFile, LARGE_INTEGER liDistanceToMove, ...)' },
  CreateDirectoryW: { category: 'Files & Folders', plain: 'Creates a new folder on disk', sig: 'BOOL CreateDirectoryW(LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes)' },
  SHGetFolderPathW: { category: 'Files & Folders', plain: 'Locates special Windows folders (AppData, Documents, Program Files)', sig: 'HRESULT SHGetFolderPathW(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags, LPWSTR pszPath)' },

  // Process & Execution
  CreateProcessW: { category: 'Runs Programs', plain: 'Spawns a new child process or external executable', sig: 'BOOL CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, ...)' },
  CreateProcessA: { category: 'Runs Programs', plain: 'Spawns a new child process or external executable', sig: 'BOOL CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, ...)' },
  ShellExecuteW: { category: 'Runs Programs', plain: 'Opens a file, URL, or application via the Windows Shell', sig: 'HINSTANCE ShellExecuteW(HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile, ...)' },
  ShellExecuteExW: { category: 'Runs Programs', plain: 'Launches an external program or UAC elevation prompt', sig: 'BOOL ShellExecuteExW(SHELLEXECUTEINFOW *pExecInfo)' },
  CreateThread: { category: 'Runs Programs', plain: 'Starts a background worker thread inside the process', sig: 'HANDLE CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, ...)' },
  ExitProcess: { category: 'Runs Programs', plain: 'Terminates the current application cleanly', sig: ' void ExitProcess(UINT uExitCode)' },
  TerminateProcess: { category: 'Runs Programs', plain: 'Forcefully kills a running process', sig: 'BOOL TerminateProcess(HANDLE hProcess, UINT uExitCode)' },

  // Memory & Dynamic Loading
  VirtualAlloc: { category: 'Memory & Code', plain: 'Allocates virtual memory pages (often used for buffers or JIT code)', sig: 'LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)' },
  VirtualProtect: { category: 'Memory & Code', plain: 'Changes memory protection flags (e.g. Read/Write/Execute)', sig: 'BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)' },
  VirtualFree: { category: 'Memory & Code', plain: 'Releases allocated virtual memory back to Windows', sig: 'BOOL VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)' },
  HeapAlloc: { category: 'Memory & Code', plain: 'Allocates a block of memory on the process heap', sig: 'LPVOID HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)' },
  LoadLibraryW: { category: 'Memory & Code', plain: 'Dynamically loads a DLL plugin into memory', sig: 'HMODULE LoadLibraryW(LPCWSTR lpLibFileName)' },
  LoadLibraryA: { category: 'Memory & Code', plain: 'Dynamically loads a DLL plugin into memory', sig: 'HMODULE LoadLibraryA(LPCSTR lpLibFileName)' },
  LoadLibraryExW: { category: 'Memory & Code', plain: 'Dynamically loads a DLL with custom search flags', sig: 'HMODULE LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)' },
  GetProcAddress: { category: 'Memory & Code', plain: 'Resolves a function pointer by name from a loaded DLL', sig: 'FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName)' },
  GetModuleHandleW: { category: 'Memory & Code', plain: 'Retrieves the base address of a loaded module or DLL', sig: 'HMODULE GetModuleHandleW(LPCWSTR lpModuleName)' },

  // Security, Debugging & Anti-Tamper
  IsDebuggerPresent: { category: 'Security & Anti-Tamper', plain: 'Checks the PEB to see if a debugger is attached to the process', sig: 'BOOL IsDebuggerPresent(void)' },
  CheckRemoteDebuggerPresent: { category: 'Security & Anti-Tamper', plain: 'Queries the kernel to detect if the process is being debugged', sig: 'BOOL CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent)' },
  OutputDebugStringW: { category: 'Security & Anti-Tamper', plain: 'Sends a diagnostic string to an attached debugger', sig: 'void OutputDebugStringW(LPCWSTR lpOutputString)' },
  SetUnhandledExceptionFilter: { category: 'Security & Anti-Tamper', plain: 'Registers a custom crash/exception handler (also used for anti-debug)', sig: 'LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilter(...)' },
  RtlCaptureContext: { category: 'Security & Anti-Tamper', plain: 'Captures CPU register state (stack unwinding / crash dumps)', sig: 'void RtlCaptureContext(PCONTEXT ContextRecord)' },
  RtlLookupFunctionEntry: { category: 'Security & Anti-Tamper', plain: 'Looks up x64 unwind metadata (.pdata) for a code address', sig: 'PRUNTIME_FUNCTION RtlLookupFunctionEntry(DWORD64 ControlPc, ...)' },

  // Registry & Configuration
  RegOpenKeyExW: { category: 'Windows Settings (Registry)', plain: 'Opens a Windows Registry key to read or modify settings', sig: 'LSTATUS RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, ...)' },
  RegQueryValueExW: { category: 'Windows Settings (Registry)', plain: 'Reads a configuration value from the Windows Registry', sig: 'LSTATUS RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, ...)' },
  RegSetValueExW: { category: 'Windows Settings (Registry)', plain: 'Writes or updates a setting in the Windows Registry', sig: 'LSTATUS RegSetValueExW(HKEY hKey, LPCWSTR lpValueName, ...)' },
  RegCreateKeyExW: { category: 'Windows Settings (Registry)', plain: 'Creates a new key in the Windows Registry', sig: 'LSTATUS RegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, ...)' },
  RegCloseKey: { category: 'Windows Settings (Registry)', plain: 'Closes an open Windows Registry handle', sig: 'LSTATUS RegCloseKey(HKEY hKey)' },

  // Networking & Web
  WSAStartup: { category: 'Internet & Network', plain: 'Initializes the Windows Sockets (Winsock) networking engine', sig: 'int WSAStartup(WORD wVersionRequired, LPWSADATA lpWSAData)' },
  socket: { category: 'Internet & Network', plain: 'Creates a raw TCP/UDP network socket', sig: 'SOCKET socket(int af, int type, int protocol)' },
  connect: { category: 'Internet & Network', plain: 'Establishes a network connection to a remote IP/port', sig: 'int connect(SOCKET s, const sockaddr *name, int namelen)' },
  send: { category: 'Internet & Network', plain: 'Transmits packets over an active network socket', sig: 'int send(SOCKET s, const char *buf, int len, int flags)' },
  recv: { category: 'Internet & Network', plain: 'Receives packets from an active network socket', sig: 'int recv(SOCKET s, char *buf, int len, int flags)' },
  getaddrinfo: { category: 'Internet & Network', plain: 'Resolves a domain name (DNS) into an IP address', sig: 'int getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, ...)' },
  InternetOpenW: { category: 'Internet & Network', plain: 'Initializes WinINet HTTP/HTTPS client networking', sig: 'HINTERNET InternetOpenW(LPCWSTR lpszAgent, DWORD dwAccessType, ...)' },
  InternetConnectW: { category: 'Internet & Network', plain: 'Opens an HTTP/HTTPS session to a remote web server', sig: 'HINTERNET InternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, ...)' },
  HttpOpenRequestW: { category: 'Internet & Network', plain: 'Creates an HTTP GET/POST request handle', sig: 'HINTERNET HttpOpenRequestW(HINTERNET hConnect, LPCWSTR lpszVerb, ...)' },
  HttpSendRequestW: { category: 'Internet & Network', plain: 'Sends an HTTP request and headers to a web server', sig: 'BOOL HttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders, ...)' },
  InternetReadFile: { category: 'Internet & Network', plain: 'Downloads response data from an HTTP/HTTPS stream', sig: 'BOOL InternetReadFile(HINTERNET hFile, LPVOID lpBuffer, ...)' },
  DnsQuery_W: { category: 'Internet & Network', plain: 'Performs direct DNS record queries (A, TXT, SRV)', sig: 'DNS_STATUS DnsQuery_W(PCWSTR pszName, WORD wType, ...)' },
  GetAdaptersAddresses: { category: 'Internet & Network', plain: 'Enumerates local network cards, MAC addresses, and IP configs', sig: 'ULONG GetAdaptersAddresses(ULONG Family, ULONG Flags, ...)' },

  // Cryptography & Certificates
  CryptAcquireContextW: { category: 'Encryption & Security', plain: 'Initializes the Windows CryptoAPI provider', sig: 'BOOL CryptAcquireContextW(HCRYPTPROV *phProv, ...)' },
  CryptEncrypt: { category: 'Encryption & Security', plain: 'Encrypts a buffer using a cryptographic key', sig: 'BOOL CryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, ...)' },
  CryptDecrypt: { category: 'Encryption & Security', plain: 'Decrypts an encrypted buffer', sig: 'BOOL CryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, ...)' },
  BCryptGenRandom: { category: 'Encryption & Security', plain: 'Generates cryptographically secure random bytes (CNG)', sig: 'NTSTATUS BCryptGenRandom(BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbBuffer, ...)' },
  CertOpenStore: { category: 'Encryption & Security', plain: 'Opens a Windows X.509 digital certificate store', sig: 'HCERTSTORE CertOpenStore(LPCSTR lpszStoreProvider, ...)' },
  CertVerifyCertificateChainPolicy: { category: 'Encryption & Security', plain: 'Verifies SSL/TLS or code-signing certificate authenticity', sig: 'BOOL CertVerifyCertificateChainPolicy(LPCSTR pszPolicyOID, ...)' },
  WinVerifyTrust: { category: 'Encryption & Security', plain: 'Validates Authenticode digital signatures on files', sig: 'LONG WinVerifyTrust(HWND hwnd, GUID *pgActionID, LPVOID pWVTData)' },

  // Graphics, Audio & Hardware (DirectX, Multimedia, HID)
  D3D11CreateDevice: { category: 'Graphics, Audio & Hardware', plain: 'Initializes the Direct3D 11 GPU rendering engine', sig: 'HRESULT D3D11CreateDevice(IDXGIAdapter *pAdapter, D3D_DRIVER_TYPE DriverType, ...)' },
  D3D12CreateDevice: { category: 'Graphics, Audio & Hardware', plain: 'Initializes the Direct3D 12 low-level GPU engine', sig: 'HRESULT D3D12CreateDevice(IUnknown *pAdapter, D3D_FEATURE_LEVEL MinimumFeatureLevel, ...)' },
  D2D1CreateFactory: { category: 'Graphics, Audio & Hardware', plain: 'Initializes Direct2D hardware-accelerated 2D vector graphics', sig: 'HRESULT D2D1CreateFactory(D2D1_FACTORY_TYPE factoryType, ...)' },
  DWriteCreateFactory: { category: 'Graphics, Audio & Hardware', plain: 'Initializes DirectWrite high-DPI font and text rendering', sig: 'HRESULT DWriteCreateFactory(DWRITE_FACTORY_TYPE factoryType, ...)' },
  CreateDXGIFactory1: { category: 'Graphics, Audio & Hardware', plain: 'Enumerates GPU display adapters and swapchains (DXGI)', sig: 'HRESULT CreateDXGIFactory1(REFIID riid, void **ppFactory)' },
  waveOutOpen: { category: 'Graphics, Audio & Hardware', plain: 'Opens a Windows waveform audio output device for sound playback', sig: 'MMRESULT waveOutOpen(LPHWAVEOUT phwo, UINT uDeviceID, ...)' },
  midiInOpen: { category: 'Graphics, Audio & Hardware', plain: 'Opens a MIDI hardware input controller (e.g. DJ deck or keyboard)', sig: 'MMRESULT midiInOpen(LPHMIDIIN phmi, UINT uDeviceID, ...)' },
  midiOutOpen: { category: 'Graphics, Audio & Hardware', plain: 'Opens a MIDI hardware output device (e.g. controller LEDs)', sig: 'MMRESULT midiOutOpen(LPHMIDIOUT phmo, UINT uDeviceID, ...)' },
  AvSetMmThreadCharacteristicsW: { category: 'Graphics, Audio & Hardware', plain: 'Boosts thread priority for real-time pro-audio / low-latency playback', sig: 'HANDLE AvSetMmThreadCharacteristicsW(LPCWSTR TaskName, LPDWORD TaskIndex)' },
  HidD_GetAttributes: { category: 'Graphics, Audio & Hardware', plain: 'Reads USB Vendor/Product IDs from a connected HID hardware controller', sig: 'BOOLEAN HidD_GetAttributes(HANDLE HidDeviceObject, PHIDD_ATTRIBUTES Attributes)' },
  SetupDiGetClassDevsW: { category: 'Graphics, Audio & Hardware', plain: 'Scans connected USB/PCI hardware devices via Windows SetupAPI', sig: 'HDEVINFO SetupDiGetClassDevsW(const GUID *ClassGuid, ...)' },

  // GUI & User Input
  CreateWindowExW: { category: 'Screen & Windows', plain: 'Creates a native application window or UI control', sig: 'HWND CreateWindowExW(DWORD dwExStyle, LPCWSTR lpClassName, LPCWSTR lpWindowName, ...)' },
  ShowWindow: { category: 'Screen & Windows', plain: 'Shows, hides, maximizes, or minimizes a window', sig: 'BOOL ShowWindow(HWND hWnd, int nCmdShow)' },
  DispatchMessageW: { category: 'Screen & Windows', plain: 'Routes Windows GUI events (clicks, keystrokes, paint) to the window procedure', sig: 'LRESULT DispatchMessageW(const MSG *lpMsg)' },
  MessageBoxW: { category: 'Screen & Windows', plain: 'Displays a modal dialog box to the user', sig: 'int MessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)' },
  MessageBoxA: { category: 'Screen & Windows', plain: 'Displays a modal dialog box to the user', sig: 'int MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)' },
  GetAsyncKeyState: { category: 'Screen & Windows', plain: 'Polls real-time keyboard or mouse button state', sig: 'SHORT GetAsyncKeyState(int vKey)' },
  OpenClipboard: { category: 'Screen & Windows', plain: 'Opens the Windows copy/paste clipboard', sig: 'BOOL OpenClipboard(HWND hWndNewOwner)' },
  GetClipboardData: { category: 'Screen & Windows', plain: 'Reads copied data from the Windows clipboard', sig: 'HANDLE GetClipboardData(UINT uFormat)' },
};

function inferDllCategoryAndMeaning(dllName, funcName) {
  if (API_DICTIONARY[funcName]) {
    return API_DICTIONARY[funcName];
  }
  const upperDll = (dllName || '').toUpperCase();
  const fn = funcName || '';

  if (/D3D|DXGI|D2D|DWRITE|OPENGL|VULKAN|GDI/i.test(upperDll)) {
    return {
      category: 'Graphics, Audio & Hardware',
      plain: `GPU / graphics rendering call (${fn}) via ${upperDll}`,
      sig: `uintptr_t ${fn}(...)`,
    };
  }
  if (/WINMM|AVRT|DSOUND|AUDIOSES|HID|SETUPAPI|AVICAP/i.test(upperDll)) {
    return {
      category: 'Graphics, Audio & Hardware',
      plain: `Audio, media, or hardware controller interface (${fn})`,
      sig: `uintptr_t ${fn}(...)`,
    };
  }
  if (/WS2_32|WININET|WINHTTP|DNSAPI|IPHLPAPI|WLDAP/i.test(upperDll)) {
    return {
      category: 'Internet & Network',
      plain: `Network or web protocol operation (${fn}) via ${upperDll}`,
      sig: `uintptr_t ${fn}(...)`,
    };
  }
  if (/CRYPT|BCRYPT|NCRYPT|SECUR32|WINTRUST/i.test(upperDll)) {
    return {
      category: 'Encryption & Security',
      plain: `Cryptography, hashing, or TLS security routine (${fn})`,
      sig: `uintptr_t ${fn}(...)`,
    };
  }
  if (/USER32|COMCTL32|COMDLG32|DWMMAPI|IMM32|OLEACC/i.test(upperDll)) {
    return {
      category: 'Screen & Windows',
      plain: `Desktop windowing, UI controls, or input handling (${fn})`,
      sig: `uintptr_t ${fn}(...)`,
    };
  }
  if (/ADVAPI32/i.test(upperDll) || /^Reg|^Service|^ LookupPrivilege/i.test(fn)) {
    return {
      category: 'Windows Settings (Registry)',
      plain: `Windows Registry, security token, or system configuration (${fn})`,
      sig: `uintptr_t ${fn}(...)`,
    };
  }
  if (/SHELL32/i.test(upperDll)) {
    return {
      category: 'Files & Folders',
      plain: `Windows Shell integration or folder operation (${fn})`,
      sig: `uintptr_t ${fn}(...)`,
    };
  }
  if (/File|Directory|Path|Volume|Disk/i.test(fn)) {
    return {
      category: 'Files & Folders',
      plain: `Filesystem or disk I/O operation (${fn})`,
      sig: `uintptr_t ${fn}(...)`,
    };
  }
  if (/Virtual|Heap|Alloc|Library|Module|ProcAddress/i.test(fn)) {
    return {
      category: 'Memory & Code',
      plain: `Memory management or dynamic module loading (${fn})`,
      sig: `uintptr_t ${fn}(...)`,
    };
  }
  if (/Process|Thread|Mutex|Event|Semaphore|CriticalSection|WaitFor/i.test(fn)) {
    return {
      category: 'Runs Programs',
      plain: `Process, multi-threading, or synchronization primitive (${fn})`,
      sig: `uintptr_t ${fn}(...)`,
    };
  }
  return {
    category: 'System & Runtime',
    plain: `Calls ${fn} in ${upperDll}`,
    sig: `uintptr_t ${fn}(...)`,
  };
}

// ============================================================================
// Lightweight x86_64 Instruction Decoder & Decompiler (Ghidra-style output)
// ============================================================================

const REG64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'];
const REG32 = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d'];
const REG8 = ['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil', 'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b'];
const JCC_NAMES = ['jo', 'jno', 'jb', 'jae', 'je', 'jne', 'jbe', 'ja', 'js', 'jns', 'jp', 'jnp', 'jl', 'jge', 'jle', 'jg'];
const JCC_CONDS = ['OVERFLOW', '!OVERFLOW', 'u<', 'u>=', '==', '!=', 'u<=', 'u>', '< 0', '>= 0', 'PARITY', '!PARITY', '<', '>=', '<=', '>'];

function formatHex64(bigVal) {
  return '0x' + bigVal.toString(16).toUpperCase();
}

/**
 * Disassembles a buffer of x86_64 machine bytes into structured instructions,
 * resolving RIP-relative imports, strings, and internal function calls.
 */
function disassembleX64Buffer(buf, baseVaBig, maxInstructions = 180, symbols = {}) {
  const instructions = [];
  let offset = 0;
  const len = buf.length;

  while (offset < len && instructions.length < maxInstructions) {
    const startOff = offset;
    const insnVa = baseVaBig + BigInt(startOff);

    // Skip legacy prefixes (0x66, 0xF2, 0xF3, segment overrides)
    let opSize16 = false;
    let repPrefix = '';
    while (offset < len) {
      const p = buf[offset];
      if (p === 0x66) { opSize16 = true; offset++; }
      else if (p === 0xf2) { repPrefix = 'repne '; offset++; }
      else if (p === 0xf3) { repPrefix = 'rep '; offset++; }
      else if (p === 0x2e || p === 0x3e || p === 0x26 || p === 0x36 || p === 0x64 || p === 0x65) { offset++; }
      else break;
    }

    // REX prefix (0x40 - 0x4F)
    let rex = 0;
    let rexW = false, rexR = false, rexX = false, rexB = false;
    if (offset < len && buf[offset] >= 0x40 && buf[offset] <= 0x4f) {
      rex = buf[offset];
      rexW = Boolean(rex & 0x08);
      rexR = Boolean(rex & 0x04);
      rexX = Boolean(rex & 0x02);
      rexB = Boolean(rex & 0x01);
      offset++;
    }

    if (offset >= len) break;
    const op = buf[offset++];

    let mnemonic = 'db';
    let operands = `0x${op.toString(16).padStart(2, '0')}`;
    let comment = '';
    let flowTarget = null;
    let flowType = null;

    const decodeModRM = (force64 = false, isByte = false) => {
      if (offset >= len) return { reg: 'rax', rm: 'rax', regIdx: 0, rmIdx: 0 };
      const modrm = buf[offset++];
      const mod = (modrm >> 6) & 3;
      const regIdx = ((modrm >> 3) & 7) + (rexR ? 8 : 0);
      const rmIdx = (modrm & 7) + (rexB ? 8 : 0);
      const rSet = isByte ? REG8 : (force64 || rexW ? REG64 : REG32);
      const regStr = rSet[regIdx] || 'rax';

      if (mod === 3) {
        return { mod, reg: regStr, rm: rSet[rmIdx] || 'rax', regIdx, rmIdx };
      }

      // SIB byte if rm & 7 == 4
      let baseStr = REG64[rmIdx];
      if ((modrm & 7) === 4 && offset < len) {
        const sib = buf[offset++];
        const scale = 1 << ((sib >> 6) & 3);
        const idx = ((sib >> 3) & 7) + (rexX ? 8 : 0);
        const base = (sib & 7) + (rexB ? 8 : 0);
        baseStr = (sib & 7) === 5 && mod === 0 ? '' : REG64[base];
        if (((sib >> 3) & 7) !== 4) {
          const idxStr = REG64[idx] + (scale > 1 ? `*${scale}` : '');
          baseStr = baseStr ? `${baseStr}+${idxStr}` : idxStr;
        }
      }

      if (mod === 0 && (modrm & 7) === 5) {
        // RIP-relative [rip + disp32]
        if (offset + 4 <= len) {
          const disp = buf.readInt32LE(offset);
          offset += 4;
          const targetVa = baseVaBig + BigInt(offset) + BigInt(disp);
          const hexTarget = formatHex64(targetVa);
          const sym = symbols.iatMap?.get(hexTarget) || symbols.stringMap?.get(hexTarget) || symbols.funcMap?.get(hexTarget);
          if (sym) comment = sym;
          return {
            mod,
            reg: regStr,
            rm: `qword ptr [rip ${disp >= 0 ? '+' : '-'} 0x${Math.abs(disp).toString(16)}]`,
            ripTarget: hexTarget,
            sym,
            regIdx,
            rmIdx,
          };
        }
      }

      let dispStr = '';
      if (mod === 1 && offset < len) {
        const disp = buf.readInt8(offset++);
        dispStr = disp >= 0 ? `+0x${disp.toString(16)}` : `-0x${Math.abs(disp).toString(16)}`;
      } else if (mod === 2 && offset + 4 <= len) {
        const disp = buf.readInt32LE(offset);
        offset += 4;
        dispStr = disp >= 0 ? `+0x${disp.toString(16)}` : `-0x${Math.abs(disp).toString(16)}`;
      }

      return { mod, reg: regStr, rm: `[${baseStr}${dispStr}]`, regIdx, rmIdx };
    };

    if (op === 0xc3) {
      mnemonic = 'ret';
      operands = '';
    } else if (op === 0xcc) {
      mnemonic = 'int3';
      operands = '';
    } else if (op === 0x90) {
      mnemonic = repPrefix ? 'pause' : 'nop';
      operands = '';
    } else if (op >= 0x50 && op <= 0x57) {
      mnemonic = 'push';
      operands = REG64[(op - 0x50) + (rexB ? 8 : 0)];
    } else if (op >= 0x58 && op <= 0x5f) {
      mnemonic = 'pop';
      operands = REG64[(op - 0x58) + (rexB ? 8 : 0)];
    } else if (op >= 0xb0 && op <= 0xb7 && offset < len) {
      const rIdx = (op - 0xb0) + (rexB ? 8 : 0);
      const imm8 = buf.readUInt8(offset++);
      mnemonic = 'mov';
      operands = `${REG8[rIdx]}, 0x${imm8.toString(16)}`;
    } else if (op >= 0xb8 && op <= 0xbf) {
      const rIdx = (op - 0xb8) + (rexB ? 8 : 0);
      mnemonic = 'mov';
      if (rexW && offset + 8 <= len) {
        const imm64 = buf.readBigUInt64LE(offset);
        offset += 8;
        operands = `${REG64[rIdx]}, 0x${imm64.toString(16)}`;
      } else if (offset + 4 <= len) {
        const imm32 = buf.readUInt32LE(offset);
        offset += 4;
        operands = `${REG32[rIdx]}, 0x${imm32.toString(16)}`;
      }
    } else if (op === 0xe8 && offset + 4 <= len) {
      const rel = buf.readInt32LE(offset);
      offset += 4;
      const targetVa = baseVaBig + BigInt(offset) + BigInt(rel);
      const hexTarget = formatHex64(targetVa);
      const sym = symbols.funcMap?.get(hexTarget) || `FUN_${targetVa.toString(16)}`;
      mnemonic = 'call';
      operands = sym;
      flowTarget = hexTarget;
      flowType = 'call';
      comment = `calls ${sym} (${hexTarget})`;
    } else if (op === 0xe9 && offset + 4 <= len) {
      const rel = buf.readInt32LE(offset);
      offset += 4;
      const targetVa = baseVaBig + BigInt(offset) + BigInt(rel);
      const hexTarget = formatHex64(targetVa);
      mnemonic = 'jmp';
      operands = symbols.funcMap?.get(hexTarget) || hexTarget;
      flowTarget = hexTarget;
      flowType = 'jmp';
    } else if (op === 0xeb && offset < len) {
      const rel = buf.readInt8(offset++);
      const targetVa = baseVaBig + BigInt(offset) + BigInt(rel);
      mnemonic = 'jmp';
      operands = formatHex64(targetVa);
      flowTarget = operands;
      flowType = 'jmp';
    } else if (op >= 0x70 && op <= 0x7f && offset < len) {
      const rel = buf.readInt8(offset++);
      const targetVa = baseVaBig + BigInt(offset) + BigInt(rel);
      mnemonic = JCC_NAMES[op - 0x70];
      operands = formatHex64(targetVa);
      flowTarget = operands;
      flowType = 'jcc';
      comment = `branch if ${JCC_CONDS[op - 0x70]}`;
    } else if (op === 0x88 || op === 0x89) {
      const m = decodeModRM(false, op === 0x88);
      mnemonic = 'mov';
      operands = `${m.rm}, ${m.reg}`;
    } else if (op === 0x8a || op === 0x8b) {
      const m = decodeModRM(false, op === 0x8a);
      mnemonic = 'mov';
      operands = `${m.reg}, ${m.rm}`;
    } else if (op === 0x8d) {
      const m = decodeModRM();
      mnemonic = 'lea';
      operands = `${m.reg}, ${m.rm}`;
      if (m.ripTarget && !m.sym) {
        comment = `addr ${m.ripTarget}`;
      }
    } else if (op === 0x31 || op === 0x33) {
      const m = decodeModRM();
      mnemonic = 'xor';
      operands = op === 0x31 ? `${m.rm}, ${m.reg}` : `${m.reg}, ${m.rm}`;
      if (m.rm === m.reg) comment = `${m.reg} = 0`;
    } else if (op === 0x84 || op === 0x85) {
      const m = decodeModRM(false, op === 0x84);
      mnemonic = 'test';
      operands = `${m.rm}, ${m.reg}`;
    } else if (op === 0x38 || op === 0x39 || op === 0x3a || op === 0x3b) {
      const m = decodeModRM(false, op === 0x38 || op === 0x3a);
      mnemonic = 'cmp';
      operands = (op === 0x38 || op === 0x39) ? `${m.rm}, ${m.reg}` : `${m.reg}, ${m.rm}`;
    } else if (op === 0x3c && offset < len) {
      const imm8 = buf.readUInt8(offset++);
      mnemonic = 'cmp';
      operands = `al, 0x${imm8.toString(16)}`;
    } else if (op === 0x3d && offset + 4 <= len) {
      const imm32 = buf.readUInt32LE(offset);
      offset += 4;
      mnemonic = 'cmp';
      operands = `${rexW ? 'rax' : 'eax'}, 0x${imm32.toString(16)}`;
    } else if (op === 0x01 || op === 0x03) {
      const m = decodeModRM();
      mnemonic = 'add';
      operands = op === 0x01 ? `${m.rm}, ${m.reg}` : `${m.reg}, ${m.rm}`;
    } else if (op === 0x29 || op === 0x2b) {
      const m = decodeModRM();
      mnemonic = 'sub';
      operands = op === 0x29 ? `${m.rm}, ${m.reg}` : `${m.reg}, ${m.rm}`;
    } else if (op === 0x21 || op === 0x23) {
      const m = decodeModRM();
      mnemonic = 'and';
      operands = op === 0x21 ? `${m.rm}, ${m.reg}` : `${m.reg}, ${m.rm}`;
    } else if (op === 0x09 || op === 0x0b) {
      const m = decodeModRM();
      mnemonic = 'or';
      operands = op === 0x09 ? `${m.rm}, ${m.reg}` : `${m.reg}, ${m.rm}`;
    } else if (op === 0x80 || op === 0x83 || op === 0x81) {
      const m = decodeModRM(false, op === 0x80);
      const grp = ['add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp'][(m.regIdx || 0) & 7];
      mnemonic = grp;
      if ((op === 0x80 || op === 0x83) && offset < len) {
        const imm8 = buf.readInt8(offset++);
        operands = `${m.rm}, ${imm8 >= 0 ? '0x' + imm8.toString(16) : '-0x' + Math.abs(imm8).toString(16)}`;
      } else if (op === 0x81 && offset + 4 <= len) {
        const imm32 = buf.readUInt32LE(offset);
        offset += 4;
        operands = `${m.rm}, 0x${imm32.toString(16)}`;
      }
    } else if (op === 0xc0 || op === 0xc1 || op === 0xd1 || op === 0xd3) {
      const m = decodeModRM(false, op === 0xc0);
      const shifts = ['rol', 'ror', 'rcl', 'rcr', 'shl', 'shr', 'sal', 'sar'];
      mnemonic = shifts[(m.regIdx || 0) & 7];
      if ((op === 0xc0 || op === 0xc1) && offset < len) {
        const imm8 = buf.readUInt8(offset++);
        operands = `${m.rm}, 0x${imm8.toString(16)}`;
      } else if (op === 0xd1) {
        operands = `${m.rm}, 1`;
      } else {
        operands = `${m.rm}, cl`;
      }
    } else if (op === 0xf6 || op === 0xf7) {
      const m = decodeModRM(false, op === 0xf6);
      const subOp = (m.regIdx || 0) & 7;
      const ops = ['test', 'test', 'not', 'neg', 'mul', 'imul', 'div', 'idiv'];
      mnemonic = ops[subOp];
      if (subOp === 0 || subOp === 1) {
        if (op === 0xf6 && offset < len) {
          const imm8 = buf.readUInt8(offset++);
          operands = `${m.rm}, 0x${imm8.toString(16)}`;
        } else if (op === 0xf7 && offset + 4 <= len) {
          const imm32 = buf.readUInt32LE(offset);
          offset += 4;
          operands = `${m.rm}, 0x${imm32.toString(16)}`;
        }
      } else {
        operands = m.rm;
      }
    } else if (op === 0xc6 || op === 0xc7) {
      const m = decodeModRM(false, op === 0xc6);
      if (op === 0xc6 && offset < len) {
        const imm8 = buf.readUInt8(offset++);
        mnemonic = 'mov';
        operands = `${m.rm}, 0x${imm8.toString(16)}`;
      } else if (op === 0xc7 && offset + 4 <= len) {
        const imm32 = buf.readUInt32LE(offset);
        offset += 4;
        mnemonic = 'mov';
        operands = `${m.rm}, 0x${imm32.toString(16)}`;
      }
    } else if (op === 0xff) {
      const m = decodeModRM(true);
      const subOp = (m.regIdx || 0) & 7;
      if (subOp === 2) {
        mnemonic = 'call';
        operands = m.sym ? `qword ptr [${m.sym}]` : m.rm;
        flowTarget = m.ripTarget || null;
        flowType = 'call_ind';
        if (m.sym) comment = `API Call: ${m.sym}`;
      } else if (subOp === 4) {
        mnemonic = 'jmp';
        operands = m.sym ? `qword ptr [${m.sym}]` : m.rm;
        flowTarget = m.ripTarget || null;
        flowType = 'jmp_ind';
        if (m.sym) comment = `Tail-Jump -> ${m.sym}`;
      } else if (subOp === 6) {
        mnemonic = 'push';
        operands = m.rm;
      } else {
        mnemonic = subOp === 0 ? 'inc' : 'dec';
        operands = m.rm;
      }
    } else if (op === 0x63) {
      const m = decodeModRM();
      mnemonic = 'movsxd';
      operands = `${m.reg}, ${m.rm}`;
    } else if (op === 0x0f && offset < len) {
      const op2 = buf[offset++];
      if (op2 >= 0x80 && op2 <= 0x8f && offset + 4 <= len) {
        const rel = buf.readInt32LE(offset);
        offset += 4;
        const targetVa = baseVaBig + BigInt(offset) + BigInt(rel);
        mnemonic = JCC_NAMES[op2 - 0x80];
        operands = formatHex64(targetVa);
        flowTarget = operands;
        flowType = 'jcc';
        comment = `branch if ${JCC_CONDS[op2 - 0x80]}`;
      } else if (op2 >= 0x90 && op2 <= 0x9f) {
        const m = decodeModRM(false, true);
        mnemonic = 'set' + JCC_NAMES[op2 - 0x90].slice(1);
        operands = m.rm;
      } else if (op2 >= 0x40 && op2 <= 0x4f) {
        const m = decodeModRM();
        mnemonic = 'cmov' + JCC_NAMES[op2 - 0x40].slice(1);
        operands = `${m.reg}, ${m.rm}`;
      } else if (op2 === 0x10 || op2 === 0x11 || op2 === 0x28 || op2 === 0x29 || op2 === 0x57) {
        const m = decodeModRM();
        const xmReg = `xmm${(m.regIdx || 0) & 15}`;
        const xmRm = m.mod === 3 ? `xmm${(m.rmIdx || 0) & 15}` : m.rm;
        if (op2 === 0x57) {
          mnemonic = 'xorps';
          operands = `${xmReg}, ${xmRm}`;
        } else if (op2 === 0x10 || op2 === 0x28) {
          mnemonic = op2 === 0x10 ? 'movups' : 'movaps';
          operands = `${xmReg}, ${xmRm}`;
        } else {
          mnemonic = op2 === 0x11 ? 'movups' : 'movaps';
          operands = `${xmRm}, ${xmReg}`;
        }
      } else if (op2 === 0xb6 || op2 === 0xb7) {
        const m = decodeModRM();
        mnemonic = 'movzx';
        operands = `${m.reg}, ${m.rm}`;
      } else if (op2 === 0xbe || op2 === 0xbf) {
        const m = decodeModRM();
        mnemonic = 'movsx';
        operands = `${m.reg}, ${m.rm}`;
      } else if (op2 === 0x1f) {
        decodeModRM();
        mnemonic = 'nop';
        operands = 'dword ptr [rax]';
      } else if (op2 === 0xaf) {
        const m = decodeModRM();
        mnemonic = 'imul';
        operands = `${m.reg}, ${m.rm}`;
      } else {
        mnemonic = `0f_${op2.toString(16)}`;
        operands = '';
      }
    }

    const rawBytes = Array.from(buf.subarray(startOff, offset))
      .map((b) => b.toString(16).toUpperCase().padStart(2, '0'))
      .join(' ');

    instructions.push({
      address: formatHex64(insnVa),
      bytes: rawBytes,
      mnemonic,
      operands,
      comment,
      flowTarget,
      flowType,
    });

    // Stop at unconditional end of basic block if followed by padding (0xCC / 0x90)
    if ((mnemonic === 'ret' || mnemonic === 'jmp') && offset < len && (buf[offset] === 0xcc || buf[offset] === 0x90)) {
      break;
    }
  }

  return instructions;
}

/**
 * Generates Ghidra-style C pseudocode from decoded x86_64 instructions.
 */
function decompileInstructionsToC(funcMeta, instructions) {
  const lines = [];
  lines.push(`// ============================================================================`);
  lines.push(`// AegisRE Decompiler Engine (Ghidra DecompInterface / x86_64 Lifter)`);
  lines.push(`// Function : ${funcMeta.name} (${funcMeta.plainTitle || 'Subroutine'})`);
  lines.push(`// Address  : ${funcMeta.address} | Size: ${funcMeta.size} bytes`);
  if (funcMeta.plainExplanation) {
    lines.push(`// Summary  : ${funcMeta.plainExplanation}`);
  }
  lines.push(`// ============================================================================`);
  lines.push(`#include <stdint.h>`);
  lines.push(`#include <stdbool.h>`);
  lines.push(`#include <windows.h>`);
  lines.push(``);
  lines.push(`${funcMeta.signature || `uint64_t ${funcMeta.name}(uint64_t param_1, uint64_t param_2, uint64_t param_3, uint64_t param_4)`}`);
  lines.push(`{`);

  // Track local stack allocation & registers
  let stackFrameSize = 0;
  let lastCmp = 'status != 0';
  let varCounter = 1;
  const bodyLines = [];
  const declaredVars = new Set(['uint64_t result = 0;']);

  for (let i = 0; i < instructions.length; i++) {
    const insn = instructions[i];
    const { mnemonic, operands, comment, address } = insn;

    if (mnemonic === 'sub' && operands.startsWith('rsp,')) {
      const m = operands.match(/0x([0-9a-fA-F]+)/);
      if (m) {
        stackFrameSize = parseInt(m[1], 16);
        bodyLines.push(`    // Allocate ${stackFrameSize} (0x${stackFrameSize.toString(16)}) bytes on stack frame`);
      }
      continue;
    }
    if (mnemonic === 'add' && operands.startsWith('rsp,')) {
      continue;
    }
    if (mnemonic === 'push' || mnemonic === 'pop' || mnemonic === 'nop' || mnemonic === 'int3') {
      continue;
    }

    if (mnemonic === 'xor') {
      const parts = operands.split(',').map((s) => s.trim());
      if (parts.length === 2 && parts[0] === parts[1]) {
        if (parts[0] === 'eax' || parts[0] === 'rax') {
          bodyLines.push(`    result = 0;`);
        } else {
          bodyLines.push(`    ${parts[0]} = 0;`);
        }
        continue;
      }
    }

    if (mnemonic === 'lea') {
      const parts = operands.split(',').map((s) => s.trim());
      if (comment) {
        bodyLines.push(`    uintptr_t ${parts[0]}_ptr = (uintptr_t)&${comment.replace(/[^a-zA-Z0-9_]/g, '_')}; // ${comment}`);
      } else {
        bodyLines.push(`    uintptr_t ${parts[0]}_ptr = (uintptr_t)(${parts[1]}); // @ ${address}`);
      }
      continue;
    }

    if (mnemonic === 'test') {
      const parts = operands.split(',').map((s) => s.trim());
      if (parts[0] === parts[1]) {
        lastCmp = `${parts[0]} == 0`;
      } else {
        lastCmp = `(${parts[0]} & ${parts[1]}) == 0`;
      }
      continue;
    }

    if (mnemonic === 'cmp') {
      const parts = operands.split(',').map((s) => s.trim());
      lastCmp = `${parts[0]} == ${parts[1]}`;
      continue;
    }

    if (mnemonic.startsWith('j') && mnemonic !== 'jmp') {
      const condComment = comment ? comment.replace('branch if ', '') : mnemonic;
      bodyLines.push(`    if (${lastCmp}) { // ${mnemonic} -> ${operands} (${condComment})`);
      bodyLines.push(`        goto LAB_${operands.replace(/^0x/, '')};`);
      bodyLines.push(`    }`);
      continue;
    }

    if (mnemonic === 'call') {
      const targetName = comment && comment.startsWith('API Call: ')
        ? comment.replace('API Call: ', '')
        : operands;
      const vName = `uVar${varCounter++}`;
      declaredVars.add(`    uint64_t ${vName};`);
      bodyLines.push(`    ${vName} = ${targetName}(rcx, rdx, r8, r9); // @ ${address}`);
      lastCmp = `${vName} != 0`;
      continue;
    }

    if (mnemonic === 'jmp') {
      if (comment && comment.startsWith('Tail-Jump -> ')) {
        const api = comment.replace('Tail-Jump -> ', '');
        bodyLines.push(`    return ${api}(param_1, param_2, param_3, param_4); // Tail-call @ ${address}`);
      } else {
        bodyLines.push(`    goto LAB_${operands.replace(/[^a-zA-Z0-9_]/g, '')}; // @ ${address}`);
      }
      continue;
    }

    if (mnemonic === 'mov' || mnemonic === 'movzx' || mnemonic === 'movsx') {
      const parts = operands.split(',').map((s) => s.trim());
      if (parts.length === 2) {
        if (parts[0] === 'eax' || parts[0] === 'rax') {
          bodyLines.push(`    result = ${parts[1]};${comment ? ' // ' + comment : ''}`);
        } else if (!parts[0].includes('rsp')) {
          bodyLines.push(`    /* ${address} */ ${parts[0]} = ${parts[1]};${comment ? ' // ' + comment : ''}`);
        }
      }
      continue;
    }

    if (mnemonic === 'ret') {
      bodyLines.push(`    return result; // @ ${address}`);
      continue;
    }

    bodyLines.push(`    /* ${address}: ${mnemonic} ${operands} */`);
  }

  for (const decl of declaredVars) {
    lines.push(`    ${decl.trim()}`);
  }
  lines.push(``);
  if (bodyLines.length === 0) {
    lines.push(`    return result;`);
  } else {
    lines.push(...bodyLines);
  }
  lines.push(`}`);

  return lines.join('\n');
}

// ============================================================================
// Full Binary Parser (PE32 / PE32+ / ELF / Mach-O / ASAR / WASM)
// ============================================================================

function computeEntropySample(fd, fileSize) {
  const sampleSize = Math.min(fileSize, 2 * 1024 * 1024);
  const buf = Buffer.alloc(sampleSize);
  fs.readSync(fd, buf, 0, sampleSize, 0);
  const freq = new Uint32Array(256);
  for (let i = 0; i < sampleSize; i++) freq[buf[i]]++;
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (freq[i] > 0) {
      const p = freq[i] / sampleSize;
      entropy -= p * Math.log2(p);
    }
  }
  return {
    entropy: Math.round(entropy * 100) / 100,
    headerBuf: buf,
  };
}

function classifyString(str) {
  if (/^https?:\/\/|[a-z0-9.-]+\.(com|org|net|io|gov|edu|dev|app|xyz)(\/|$)/i.test(str)) {
    return { category: 'Web Link / URL', plain: 'Website URL or remote server endpoint' };
  }
  if (/^[a-zA-Z]:\\|^\\\\|HKEY_|CurrentVersion\\Run|\/etc\/|\/usr\/|\.dll$|\.exe$|\.sys$|\.pdb$/i.test(str)) {
    return { category: 'File Path / System Setting', plain: 'File path, DLL module, debug symbol path, or Registry key' };
  }
  if (/asio|cuda|direct3d|shader|hlsl|opengl|vulkan|midi|vst|audio|codec|ffmpeg|stem|deck|mixer|sample/i.test(str)) {
    return { category: 'Audio, GPU & Engine Clues', plain: 'Multimedia, DSP audio, GPU shader, or hardware engine identifier' };
  }
  if (/license|serial|activation|trial|key|signature|password|secret|token|apikey|bearer|encrypt|decrypt|admin|error|fail|warning/i.test(str)) {
    return { category: 'Notable Keyword / Command', plain: 'Licensing, security, command, or diagnostic message' };
  }
  return { category: 'App Text', plain: 'Embedded string literal or identifier inside the binary' };
}

function extractStringsFromBuffer(buf, baseRva = 0, maxStrings = 1500) {
  const results = [];
  const seen = new Set();
  const scanLen = Math.min(buf.length, 16 * 1024 * 1024);

  // 1. Scan ASCII strings
  let start = -1;
  let current = '';
  for (let i = 0; i < scanLen; i++) {
    const b = buf[i];
    if (b >= 32 && b <= 126) {
      if (start === -1) start = i;
      current += String.fromCharCode(b);
    } else {
      if (current.length >= 5 && current.length <= 240) {
        const trimmed = current.trim();
        if (trimmed.length >= 5 && /[a-zA-Z]{3,}/.test(trimmed) && !seen.has(trimmed)) {
          seen.add(trimmed);
          const info = classifyString(trimmed);
          results.push({
            offset: '0x' + (baseRva + start).toString(16).toUpperCase().padStart(8, '0'),
            section: info.category,
            type: 'ASCII',
            value: trimmed,
            plain: info.plain,
          });
          if (results.length >= maxStrings) break;
        }
      }
      start = -1;
      current = '';
    }
  }

  // 2. Scan UTF-16LE wide strings if room remains
  if (results.length < maxStrings) {
    const wideLimit = Math.min(scanLen - 2, 4 * 1024 * 1024);
    let wStart = -1;
    let wCur = '';
    for (let i = 0; i < wideLimit; i += 2) {
      const lo = buf[i];
      const hi = buf[i + 1];
      if (hi === 0 && lo >= 32 && lo <= 126) {
        if (wStart === -1) wStart = i;
        wCur += String.fromCharCode(lo);
      } else {
        if (wCur.length >= 6 && wCur.length <= 200) {
          const trimmed = wCur.trim();
          if (trimmed.length >= 6 && /[a-zA-Z]{4,}/.test(trimmed) && !seen.has(trimmed)) {
            seen.add(trimmed);
            const info = classifyString(trimmed);
            results.push({
              offset: '0x' + (baseRva + wStart).toString(16).toUpperCase().padStart(8, '0'),
              section: info.category,
              type: 'UTF-16LE',
              value: trimmed,
              plain: info.plain,
            });
            if (results.length >= maxStrings) break;
          }
        }
        wStart = -1;
        wCur = '';
      }
    }
  }

  const priority = {
    'Web Link / URL': 1,
    'Notable Keyword / Command': 2,
    'Audio, GPU & Engine Clues': 3,
    'File Path / System Setting': 4,
    'App Text': 5,
  };
  results.sort((a, b) => (priority[a.section] || 9) - (priority[b.section] || 9));
  return results;
}

function formatHexPreview(buf, baseAddress = 0, maxBytes = 1024) {
  const hexLines = [];
  const hexLen = Math.min(buf.length, maxBytes);
  for (let i = 0; i < hexLen; i += 16) {
    const slice = buf.subarray(i, Math.min(i + 16, hexLen));
    const hexPart = Array.from(slice)
      .map((b) => b.toString(16).toUpperCase().padStart(2, '0'))
      .join(' ')
      .padEnd(47, ' ');
    const asciiPart = Array.from(slice)
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
      .join('');
    hexLines.push(`0x${(baseAddress + i).toString(16).toUpperCase().padStart(8, '0')}  ${hexPart}  |${asciiPart}|`);
  }
  return hexLines.join('\n');
}

/**
 * Full Deep Static Inspection of any PE/ELF/Binary target.
 */
function analyzeBinaryTarget(filePath) {
  const stats = fs.statSync(filePath);
  const fileSize = stats.size;
  const fd = fs.openSync(filePath, 'r');

  try {
    const { entropy, headerBuf } = computeEntropySample(fd, fileSize);
    const sha256 = crypto.createHash('sha256').update(headerBuf).digest('hex');
    const md5 = crypto.createHash('md5').update(headerBuf).digest('hex');

    let format = 'Binary / Data File';
    let plainFormat = 'General Application or Data File';
    let arch = 'Unknown';
    let subsystem = 'Desktop / System';
    let compileDate = new Date(stats.mtimeMs).toLocaleDateString();
    let imageBase = 0x140000000n;
    let entryRva = 0;
    let is64Bit = true;

    const sections = [];
    const securityFeatures = [];
    const imports = [];
    const exportsList = [];
    const functions = [];
    const iatMap = new Map();
    const funcMap = new Map();
    let strings = [];
    let totalFunctionCount = 0;

    // Check if Windows PE ('MZ')
    if (headerBuf.length >= 64 && headerBuf[0] === 0x4d && headerBuf[1] === 0x5a) {
      const peOffset = headerBuf.readUInt32LE(0x3c);
      if (peOffset > 0 && peOffset + 24 < headerBuf.length && headerBuf.toString('ascii', peOffset, peOffset + 4) === 'PE\0\0') {
        const machine = headerBuf.readUInt16LE(peOffset + 4);
        const numSections = headerBuf.readUInt16LE(peOffset + 6);
        const timestamp = headerBuf.readUInt32LE(peOffset + 8);
        const optHeaderSize = headerBuf.readUInt16LE(peOffset + 20);

        if (timestamp > 0) {
          compileDate = new Date(timestamp * 1000).toLocaleDateString();
        }

        plainFormat = filePath.toLowerCase().endsWith('.dll')
          ? 'Windows Dynamic Link Library (.dll)'
          : filePath.toLowerCase().endsWith('.sys')
          ? 'Windows Kernel Driver (.sys)'
          : 'Windows Executable Program (.exe)';

        if (machine === 0x8664) {
          arch = '64-bit Intel/AMD (x86_64)';
          format = 'PE32+ (64-bit Windows)';
          is64Bit = true;
        } else if (machine === 0x014c) {
          arch = '32-bit Intel/AMD (x86)';
          format = 'PE32 (32-bit Windows)';
          is64Bit = false;
        } else if (machine === 0xaa64) {
          arch = '64-bit ARM (ARM64)';
          format = 'PE32+ (ARM64 Windows)';
          is64Bit = true;
        }

        const optOffset = peOffset + 24;
        const magic = headerBuf.readUInt16LE(optOffset);
        is64Bit = magic === 0x20b;

        entryRva = headerBuf.readUInt32LE(optOffset + 16);
        imageBase = is64Bit
          ? headerBuf.readBigUInt64LE(optOffset + 24)
          : BigInt(headerBuf.readUInt32LE(optOffset + 28));

        const subsysVal = headerBuf.readUInt16LE(optOffset + 68);
        const dllChars = headerBuf.readUInt16LE(optOffset + 70);
        if (subsysVal === 2) subsystem = 'Graphical Windowed App (GUI)';
        else if (subsysVal === 3) subsystem = 'Command-Line / Console Tool';
        else if (subsysVal === 1) subsystem = 'Windows Kernel / System Driver';

        if (dllChars & 0x0020) securityFeatures.push('High-Entropy 64-bit ASLR');
        if (dllChars & 0x0040) securityFeatures.push('ASLR (Randomized Memory Protection)');
        if (dllChars & 0x0100) securityFeatures.push('DEP / NX (Prevents Data Execution)');
        if (dllChars & 0x0400) securityFeatures.push('No SEH (Structured Exception Protection)');
        if (dllChars & 0x4000) securityFeatures.push('CFG (Control Flow Guard)');

        // Read Data Directories
        const dataDirOffset = optOffset + (is64Bit ? 112 : 96);
        const dataDirs = [];
        for (let d = 0; d < 16; d++) {
          const dOff = dataDirOffset + d * 8;
          if (dOff + 8 <= headerBuf.length) {
            dataDirs.push({
              rva: headerBuf.readUInt32LE(dOff),
              size: headerBuf.readUInt32LE(dOff + 4),
            });
          } else {
            dataDirs.push({ rva: 0, size: 0 });
          }
        }

        // Read Section Headers
        const secTableOffset = optOffset + optHeaderSize;
        for (let i = 0; i < Math.min(numSections, 32); i++) {
          const sOff = secTableOffset + i * 40;
          if (sOff + 40 > headerBuf.length) break;
          const secName = headerBuf.toString('ascii', sOff, sOff + 8).replace(/\0+$/, '') || `sec_${i}`;
          const vSize = headerBuf.readUInt32LE(sOff + 8);
          const vAddr = headerBuf.readUInt32LE(sOff + 12);
          const rawSize = headerBuf.readUInt32LE(sOff + 16);
          const rawPtr = headerBuf.readUInt32LE(sOff + 20);
          const chars = headerBuf.readUInt32LE(sOff + 36);
          sections.push({
            name: secName,
            vAddr,
            vSize,
            rawPtr,
            rawSize,
            chars,
            address: '0x' + (imageBase + BigInt(vAddr)).toString(16).toUpperCase(),
            size: vSize || rawSize,
          });
        }

        // Helper: Convert RVA to file offset using section headers
        const rvaToFileOffset = (rva) => {
          for (const s of sections) {
            const secSpan = Math.max(s.vSize, s.rawSize);
            if (rva >= s.vAddr && rva < s.vAddr + secSpan) {
              return s.rawPtr + (rva - s.vAddr);
            }
          }
          return rva < headerBuf.length ? rva : -1;
        };

        // Helper: Read bytes at RVA directly from the file descriptor
        const readAtRva = (rva, byteLen) => {
          const fileOff = rvaToFileOffset(rva);
          if (fileOff < 0 || fileOff >= fileSize) return null;
          const actualLen = Math.min(byteLen, fileSize - fileOff);
          if (actualLen <= 0) return null;
          const out = Buffer.alloc(actualLen);
          fs.readSync(fd, out, 0, actualLen, fileOff);
          return out;
        };

        const readAsciiAtRva = (rva, maxLen = 128) => {
          const b = readAtRva(rva, maxLen);
          if (!b) return '';
          let end = 0;
          while (end < b.length && b[end] !== 0) end++;
          return b.toString('ascii', 0, end);
        };

        // 1. Parse Real PE Import Directory (DataDirectory[1])
        const importDir = dataDirs[1];
        if (importDir && importDir.rva > 0 && importDir.size > 0) {
          const descBuf = readAtRva(importDir.rva, Math.min(importDir.size + 40, 8192));
          if (descBuf) {
            for (let dIdx = 0; dIdx + 20 <= descBuf.length; dIdx += 20) {
              const iltRva = descBuf.readUInt32LE(dIdx);
              const nameRva = descBuf.readUInt32LE(dIdx + 12);
              const iatRva = descBuf.readUInt32LE(dIdx + 16);
              if (iltRva === 0 && nameRva === 0 && iatRva === 0) break;

              const dllName = readAsciiAtRva(nameRva, 96) || 'UNKNOWN.DLL';
              const thunkRva = iltRva || iatRva;
              const ptrSize = is64Bit ? 8 : 4;
              const thunkBuf = readAtRva(thunkRva, 4096);
              if (!thunkBuf) continue;

              for (let t = 0; t + ptrSize <= thunkBuf.length; t += ptrSize) {
                let funcName = '';
                const iatEntryVa = formatHex64(imageBase + BigInt((iatRva || thunkRva) + t));

                if (is64Bit) {
                  const val = thunkBuf.readBigUInt64LE(t);
                  if (val === 0n) break;
                  if (val & 0x8000000000000000n) {
                    const ord = Number(val & 0xffffn);
                    funcName = `Ordinal_${ord}`;
                  } else {
                    const hintNameRva = Number(val & 0x7fffffffn);
                    funcName = readAsciiAtRva(hintNameRva + 2, 128);
                  }
                } else {
                  const val = thunkBuf.readUInt32LE(t);
                  if (val === 0) break;
                  if (val & 0x80000000) {
                    funcName = `Ordinal_${val & 0xffff}`;
                  } else {
                    funcName = readAsciiAtRva((val & 0x7fffffff) + 2, 128);
                  }
                }

                if (funcName) {
                  const info = inferDllCategoryAndMeaning(dllName, funcName);
                  imports.push({
                    dll: dllName.toUpperCase(),
                    function: funcName,
                    address: iatEntryVa,
                    category: info.category,
                    plain: info.plain,
                    signature: info.sig,
                  });
                  iatMap.set(iatEntryVa, `${dllName}!${funcName}`);
                }
              }
            }
          }
        }

        // 2. Parse Real PE Export Directory (DataDirectory[0])
        const exportDir = dataDirs[0];
        if (exportDir && exportDir.rva > 0 && exportDir.size >= 40) {
          const expHeader = readAtRva(exportDir.rva, 40);
          if (expHeader) {
            const numNames = Math.min(expHeader.readUInt32LE(24), 500);
            const addrTableRva = expHeader.readUInt32LE(28);
            const namePtrRva = expHeader.readUInt32LE(32);
            const ordTableRva = expHeader.readUInt32LE(36);

            const namePtrs = readAtRva(namePtrRva, numNames * 4);
            const ords = readAtRva(ordTableRva, numNames * 2);
            const addrs = readAtRva(addrTableRva, Math.max(numNames, 256) * 4);

            if (namePtrs && ords && addrs) {
              for (let i = 0; i < numNames; i++) {
                const nRva = namePtrs.readUInt32LE(i * 4);
                const ord = ords.readUInt16LE(i * 2);
                if (ord * 4 + 4 <= addrs.length) {
                  const fnRva = addrs.readUInt32LE(ord * 4);
                  const fnName = readAsciiAtRva(nRva, 128);
                  if (fnName && fnRva > 0) {
                    const fnVa = formatHex64(imageBase + BigInt(fnRva));
                    exportsList.push({ name: fnName, rva: fnRva, address: fnVa });
                    funcMap.set(fnVa, fnName);
                  }
                }
              }
            }
          }
        }

        // 3. Extract Strings from .rdata / .rodata / .data (not just the first 4MB of .text!)
        const rdataSec = sections.find((s) => s.name === '.rdata' || s.name === '.rodata');
        if (rdataSec && rdataSec.rawSize > 0) {
          const rdataBuf = readAtRva(rdataSec.vAddr, Math.min(rdataSec.rawSize, 16 * 1024 * 1024));
          if (rdataBuf) {
            strings = extractStringsFromBuffer(rdataBuf, rdataSec.vAddr, 1500);
          }
        }
        if (strings.length < 100) {
          strings = extractStringsFromBuffer(headerBuf, 0, 1000);
        }

        // 4. Discover Real Functions from Entry Point, Exports, and .pdata Exception Directory
        const addDisassembledFunction = (rva, name, size, plainTitle, plainExplanation, category = 'Code') => {
          const vaBig = imageBase + BigInt(rva);
          const addrHex = formatHex64(vaBig);
          if (functions.some((f) => f.address === addrHex)) return;

          const codeBuf = readAtRva(rva, Math.min(Math.max(size, 64), 1024));
          const disasm = codeBuf
            ? disassembleX64Buffer(codeBuf, vaBig, 140, { iatMap, funcMap })
            : [];
          const callsCount = disasm.filter((d) => d.mnemonic === 'call').length;
          const sig = `uint64_t ${name.replace(/[^a-zA-Z0-9_]/g, '_')}(uint64_t rcx, uint64_t rdx, uint64_t r8, uint64_t r9)`;
          const decompiledC = decompileInstructionsToC(
            { name, address: addrHex, size, signature: sig, plainTitle, plainExplanation },
            disasm
          );

          functions.push({
            address: addrHex,
            rva,
            name,
            size,
            calls: callsCount,
            category,
            signature: sig,
            plainTitle,
            plainExplanation,
            disassembly: disasm,
            decompiled: decompiledC,
          });
        };

        // 4a. Entry Point
        if (entryRva > 0) {
          funcMap.set(formatHex64(imageBase + BigInt(entryRva)), 'entry');
          addDisassembledFunction(
            entryRva,
            'entry',
            256,
            'Entry Point (CRT / App Startup)',
            `Primary execution entry point of ${path.basename(filePath)} at RVA 0x${entryRva.toString(16).toUpperCase()}. Initializes security cookies, CRT runtime, and invokes WinMain/main.`,
            'Entry Point'
          );

          // Follow direct calls from entry point (e.g. __scrt_common_main_seh / security_init_cookie)
          const entryFn = functions[0];
          if (entryFn && entryFn.disassembly) {
            let subIdx = 1;
            for (const insn of entryFn.disassembly) {
              if ((insn.flowType === 'call' || insn.flowType === 'jmp') && insn.flowTarget) {
                const targetBig = BigInt(insn.flowTarget);
                const targetRva = Number(targetBig - imageBase);
                if (targetRva > 0 && targetRva < fileSize) {
                  const helperName = insn.flowType === 'call' && subIdx === 1
                    ? '__security_init_cookie'
                    : insn.flowType === 'jmp'
                    ? '__scrt_common_main_seh'
                    : `sub_${targetBig.toString(16).toUpperCase()}`;
                  funcMap.set(insn.flowTarget, helperName);
                  addDisassembledFunction(
                    targetRva,
                    helperName,
                    320,
                    helperName === '__security_init_cookie'
                      ? 'Security Stack Cookie Init'
                      : helperName === '__scrt_common_main_seh'
                      ? 'CRT Main Dispatcher (__scrt_common_main_seh)'
                      : `Startup Subroutine #${subIdx}`,
                    `Called directly from Entry Point (${insn.address}) via ${insn.mnemonic}.`,
                    'Startup & CRT'
                  );

                  // If this is __scrt_common_main_seh, inspect its calls to discover WinMain!
                  if (helperName === '__scrt_common_main_seh') {
                    const crtFn = functions.find((f) => f.name === '__scrt_common_main_seh');
                    if (crtFn && crtFn.disassembly) {
                      for (let k = 0; k < crtFn.disassembly.length; k++) {
                        const ci = crtFn.disassembly[k];
                        // Pattern: lea rcx, [imageBase] followed by call WinMain
                        if (ci.mnemonic === 'lea' && ci.operands.startsWith('rcx,') && ci.comment === `addr ${formatHex64(imageBase)}`) {
                          const nextCall = crtFn.disassembly[k + 1];
                          if (nextCall && nextCall.flowType === 'call' && nextCall.flowTarget) {
                            const winMainVa = BigInt(nextCall.flowTarget);
                            const winMainRva = Number(winMainVa - imageBase);
                            if (winMainRva > 0 && winMainRva < fileSize) {
                              funcMap.set(nextCall.flowTarget, 'WinMain');
                              nextCall.operands = 'WinMain';
                              nextCall.comment = `calls WinMain (${nextCall.flowTarget})`;
                              addDisassembledFunction(
                                winMainRva,
                                'WinMain',
                                512,
                                'WinMain (Application Main Function)',
                                `Primary GUI application entry function (WinMain) at ${nextCall.flowTarget} discovered via CRT dispatcher.`,
                                'Entry Point'
                              );
                            }
                          }
                        }
                      }
                    }
                  }
                  subIdx++;
                }
              }
            }
          }
        }

        // 4b. Exported Functions
        for (const exp of exportsList.slice(0, 40)) {
          addDisassembledFunction(
            exp.rva,
            exp.name,
            256,
            `Export: ${exp.name}`,
            `Publicly exported symbol "${exp.name}" at ${exp.address}.`,
            'Exported Symbol'
          );
        }

        // 4c. Parse .pdata (DataDirectory[3]) for real x64 function boundaries
        const pdataDir = dataDirs[3];
        if (pdataDir && pdataDir.rva > 0 && pdataDir.size >= 12) {
          totalFunctionCount = Math.floor(pdataDir.size / 12);
          // Read sample of .pdata entries (spread across the binary + largest/notable routines)
          const sampleBytes = Math.min(pdataDir.size, 24000 * 12);
          const pdataBuf = readAtRva(pdataDir.rva, sampleBytes);
          if (pdataBuf) {
            const entriesCount = Math.floor(pdataBuf.length / 12);
            // Collect all valid entries in the buffer
            const rawEntries = [];
            for (let i = 0; i < entriesCount; i++) {
              const beginRva = pdataBuf.readUInt32LE(i * 12);
              const endRva = pdataBuf.readUInt32LE(i * 12 + 4);
              const fnSize = endRva - beginRva;
              if (beginRva > 0 && endRva > beginRva && fnSize >= 16 && fnSize < 200000) {
                rawEntries.push({ index: i, beginRva, endRva, size: fnSize });
                const vaHex = formatHex64(imageBase + BigInt(beginRva));
                if (!funcMap.has(vaHex)) {
                  funcMap.set(vaHex, `FUN_${(imageBase + BigInt(beginRva)).toString(16)}`);
                }
              }
            }

            // Pick a curated mix of functions (first 40 + 80 evenly spaced across the binary)
            const selectedEntries = [];
            const seenRvas = new Set(functions.map((f) => f.rva));
            for (let i = 0; i < Math.min(40, rawEntries.length); i++) {
              if (!seenRvas.has(rawEntries[i].beginRva)) {
                seenRvas.add(rawEntries[i].beginRva);
                selectedEntries.push(rawEntries[i]);
              }
            }
            const step = Math.max(1, Math.floor(rawEntries.length / 100));
            for (let i = 0; i < rawEntries.length && selectedEntries.length < 140; i += step) {
              if (!seenRvas.has(rawEntries[i].beginRva)) {
                seenRvas.add(rawEntries[i].beginRva);
                selectedEntries.push(rawEntries[i]);
              }
            }

            for (const entry of selectedEntries) {
              const vaBig = imageBase + BigInt(entry.beginRva);
              const fnName = `FUN_${vaBig.toString(16)}`;
              addDisassembledFunction(
                entry.beginRva,
                fnName,
                entry.size,
                `${fnName} (${entry.size} bytes)`,
                `Native x86_64 function #${entry.index + 1} discovered via PE .pdata Exception Directory.`,
                'Native Function (.pdata)'
              );
            }
          }
        }
      }
    } else {
      // Fallback for non-PE files
      strings = extractStringsFromBuffer(headerBuf, 0, 800);
    }

    // Build Plain-English Capability Cards from real parsed imports & sections
    const capabilityMap = new Map();
    for (const imp of imports) {
      if (!capabilityMap.has(imp.category)) {
        capabilityMap.set(imp.category, []);
      }
      const list = capabilityMap.get(imp.category);
      const label = `${imp.dll}!${imp.function} — ${imp.plain}`;
      if (!list.includes(label)) {
        list.push(label);
      }
    }

    // Detect special sections (e.g. NVIDIA CUDA .nv_fatb, resources .rsrc)
    if (sections.some((s) => s.name.toLowerCase().includes('nv_fatb') || s.name.toLowerCase().includes('nvfat'))) {
      if (!capabilityMap.has('GPU Compute & AI (CUDA)')) {
        capabilityMap.set('GPU Compute & AI (CUDA)', []);
      }
      capabilityMap.get('GPU Compute & AI (CUDA)').push(
        'Embedded NVIDIA CUDA Fatbin (.nv_fatb) — Runs real-time GPU kernels (e.g., AI Stem separation / neural audio DSP)'
      );
    }

    const rsrcSec = sections.find((s) => s.name === '.rsrc');
    if (rsrcSec && rsrcSec.size > 50 * 1024 * 1024) {
      if (!capabilityMap.has('Embedded Assets & Skins (.rsrc)')) {
        capabilityMap.set('Embedded Assets & Skins (.rsrc)', []);
      }
      capabilityMap.get('Embedded Assets & Skins (.rsrc)').push(
        `Contains ${(rsrcSec.size / (1024 * 1024)).toFixed(1)} MB of embedded UI skins, graphics, shaders, and audio assets`
      );
    }

    const capabilities = Array.from(capabilityMap.entries()).map(([title, items]) => ({
      title,
      count: items.length,
      examples: items.slice(0, 6),
    }));

    const isPacked = entropy >= 7.25;
    const packingExplanation = isPacked
      ? `High entropy (${entropy}/8.0). Significant portions of this binary are compressed, packed, or encrypted.`
      : `Unpacked native structure (Entropy ${entropy}/8.0). Machine code, ${imports.length} imported APIs across ${new Set(imports.map((i) => i.dll)).size} DLLs, and ${totalFunctionCount || functions.length} functions are directly readable.`;

    const fileSizeFormatted =
      fileSize > 1024 * 1024
        ? `${(fileSize / (1024 * 1024)).toFixed(2)} MB`
        : `${(fileSize / 1024).toFixed(1)} KB`;

    return {
      success: true,
      target: {
        path: filePath,
        name: path.basename(filePath),
        size: fileSize,
        sizeFormatted: fileSizeFormatted,
        format,
        plainFormat,
        arch,
        subsystem,
        compileDate,
        imageBase: formatHex64(imageBase),
        entryPoint: formatHex64(imageBase + BigInt(entryRva)),
        totalFunctionsDiscovered: totalFunctionCount || functions.length,
        totalDllsImported: new Set(imports.map((i) => i.dll)).size,
        entropy,
        isPacked,
        packingExplanation,
        securityFeatures: securityFeatures.length > 0 ? securityFeatures : ['Standard PE Header'],
        sections: sections.map((s) => `${s.name} (${s.size.toLocaleString()} bytes @ ${s.address})`),
        sectionDetails: sections,
        exports: exportsList,
        hashes: { sha256, md5 },
        capabilities,
        hexPreview: formatHexPreview(headerBuf, 0, 1024),
        summary: `This is a ${plainFormat} (${arch}) built for ${subsystem}. ${packingExplanation}`,
      },
      functions,
      strings,
      imports,
    };
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * On-demand disassembly & decompilation of any virtual address or RVA in the target file.
 */
function disassembleFunctionAtAddress(filePath, targetAddressStr, byteLength = 512) {
  const stats = fs.statSync(filePath);
  const fd = fs.openSync(filePath, 'r');
  try {
    const hdr = Buffer.alloc(Math.min(stats.size, 8192));
    fs.readSync(fd, hdr, 0, hdr.length, 0);
    if (hdr[0] !== 0x4d || hdr[1] !== 0x5a) {
      return { success: false, error: 'Target is not a valid PE binary' };
    }
    const peOff = hdr.readUInt32LE(0x3c);
    const numSections = hdr.readUInt16LE(peOff + 6);
    const optSize = hdr.readUInt16LE(peOff + 20);
    const optOff = peOff + 24;
    const is64 = hdr.readUInt16LE(optOff) === 0x20b;
    const imageBase = is64 ? hdr.readBigUInt64LE(optOff + 24) : BigInt(hdr.readUInt32LE(optOff + 28));

    const sections = [];
    const secTableOff = optOff + optSize;
    for (let i = 0; i < Math.min(numSections, 32); i++) {
      const sOff = secTableOff + i * 40;
      sections.push({
        name: hdr.toString('ascii', sOff, sOff + 8).replace(/\0+$/, ''),
        vSize: hdr.readUInt32LE(sOff + 8),
        vAddr: hdr.readUInt32LE(sOff + 12),
        rawSize: hdr.readUInt32LE(sOff + 16),
        rawPtr: hdr.readUInt32LE(sOff + 20),
      });
    }

    const cleanHex = targetAddressStr.trim().replace(/^0x/i, '');
    let targetVa = BigInt('0x' + cleanHex);
    if (targetVa < imageBase) {
      targetVa = imageBase + targetVa;
    }
    const rva = Number(targetVa - imageBase);

    let fileOff = -1;
    for (const s of sections) {
      const span = Math.max(s.vSize, s.rawSize);
      if (rva >= s.vAddr && rva < s.vAddr + span) {
        fileOff = s.rawPtr + (rva - s.vAddr);
        break;
      }
    }

    if (fileOff < 0 || fileOff >= stats.size) {
      return { success: false, error: `Address 0x${targetVa.toString(16).toUpperCase()} is outside mapped PE sections.` };
    }

    const readLen = Math.min(byteLength, stats.size - fileOff);
    const codeBuf = Buffer.alloc(readLen);
    fs.readSync(fd, codeBuf, 0, readLen, fileOff);

    const fnName = `FUN_${targetVa.toString(16).toUpperCase()}`;
    const addrHex = formatHex64(targetVa);
    const disasm = disassembleX64Buffer(codeBuf, targetVa, 180, {});
    const decompiled = decompileInstructionsToC(
      {
        name: fnName,
        address: addrHex,
        size: readLen,
        signature: `uint64_t ${fnName}(uint64_t rcx, uint64_t rdx, uint64_t r8, uint64_t r9)`,
        plainTitle: `Custom Disassembled Routine @ ${addrHex}`,
        plainExplanation: `Directly decoded from file offset 0x${fileOff.toString(16).toUpperCase()} (RVA 0x${rva.toString(16).toUpperCase()}).`,
      },
      disasm
    );

    return {
      success: true,
      function: {
        address: addrHex,
        rva,
        name: fnName,
        size: readLen,
        calls: disasm.filter((d) => d.mnemonic === 'call').length,
        category: 'Direct Address Lookup',
        signature: `uint64_t ${fnName}(uint64_t rcx, uint64_t rdx, uint64_t r8, uint64_t r9)`,
        plainTitle: `${fnName} (@ ${addrHex})`,
        plainExplanation: `Live disassembled & decompiled x86_64 code at ${addrHex} (File Offset 0x${fileOff.toString(16).toUpperCase()}).`,
        disassembly: disasm,
        decompiled,
      },
    };
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Checks for a local Ghidra installation (analyzeHeadless.bat) so users can also run
 * full NSA Ghidra Headless decompilation directly from AegisRE Studio.
 */
function detectGhidraInstallation(customPath) {
  const candidates = [];
  if (customPath) candidates.push(customPath);
  if (process.env.GHIDRA_INSTALL_DIR) candidates.push(process.env.GHIDRA_INSTALL_DIR);

  const searchRoots = ['C:\\', 'C:\\Program Files', 'C:\\ghidra', path.join(process.env.USERPROFILE || '', 'Downloads')];
  for (const root of searchRoots) {
    try {
      if (fs.existsSync(root)) {
        const entries = fs.readdirSync(root);
        for (const e of entries) {
          if (e.toLowerCase().startsWith('ghidra_')) {
            candidates.push(path.join(root, e));
          }
        }
      }
    } catch (_) {}
  }

  for (const dir of candidates) {
    const bat = path.join(dir, 'support', 'analyzeHeadless.bat');
    if (fs.existsSync(bat)) {
      return { installed: true, path: dir, headlessBat: bat };
    }
    if (dir.endsWith('analyzeHeadless.bat') && fs.existsSync(dir)) {
      return { installed: true, path: path.resolve(dir, '../..'), headlessBat: dir };
    }
  }
  return { installed: false, path: null, headlessBat: null };
}

module.exports = {
  analyzeBinaryTarget,
  disassembleFunctionAtAddress,
  detectGhidraInstallation,
};
