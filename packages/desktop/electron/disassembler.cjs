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
  if (sampleSize > 0) {
    fs.readSync(fd, buf, 0, sampleSize, 0);
  }
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

function computeFileHashes(fd, fileSize, headerBuf) {
  const maxHashBytes = Math.min(fileSize, 64 * 1024 * 1024);
  const sha = crypto.createHash('sha256');
  const md5 = crypto.createHash('md5');
  if (maxHashBytes <= headerBuf.length) {
    sha.update(headerBuf.subarray(0, maxHashBytes));
    md5.update(headerBuf.subarray(0, maxHashBytes));
  } else {
    sha.update(headerBuf);
    md5.update(headerBuf);
    const chunkBuf = Buffer.alloc(4 * 1024 * 1024);
    let pos = headerBuf.length;
    while (pos < maxHashBytes) {
      const toRead = Math.min(chunkBuf.length, maxHashBytes - pos);
      const bytesRead = fs.readSync(fd, chunkBuf, 0, toRead, pos);
      if (bytesRead <= 0) break;
      const view = chunkBuf.subarray(0, bytesRead);
      sha.update(view);
      md5.update(view);
      pos += bytesRead;
    }
  }
  return {
    sha256: sha.digest('hex'),
    md5: md5.digest('hex'),
  };
}

function readFileSlice(fd, fileSize, offset, length) {
  if (offset < 0 || offset >= fileSize || length <= 0) return Buffer.alloc(0);
  const actual = Math.min(length, fileSize - offset);
  const out = Buffer.alloc(actual);
  fs.readSync(fd, out, 0, actual, offset);
  return out;
}

const RUNTIME_INDICATOR_RULES = [
  { pattern: /\b(ipcMain|ipcRenderer|contextBridge|BrowserWindow|webContents|remote)\b/g, dll: 'ELECTRON', category: 'Electron IPC & Desktop Bridge', plain: 'Electron main/renderer process IPC or window bridge API' },
  { pattern: /\b(child_process|execSync|spawnSync|execFile)\b/g, dll: 'NODE.JS', category: 'Runs Programs', plain: 'Spawns child processes or shell commands from Node.js' },
  { pattern: /\b(createCipheriv|createDecipheriv|subtle\.encrypt|subtle\.decrypt|createHash)\b/g, dll: 'CRYPTO', category: 'Encryption & Security', plain: 'Performs symmetric encryption, decryption, or cryptographic hashing' },
  { pattern: /\b(WebSocket|XMLHttpRequest|axios|https\.request|http\.request)\b/g, dll: 'NETWORK', category: 'Internet & Network', plain: 'Makes outbound HTTP/HTTPS or WebSocket requests' },
  { pattern: /\b(sqlite3_open|sqlite3_exec|indexedDB|localStorage)\b/g, dll: 'STORAGE', category: 'Files & Folders', plain: 'Reads or persists structured data in local database or storage' },
  { pattern: /\b(dlopen|dlsym|pthread_create|mmap|mprotect|execve|fork|ptrace)\b/g, dll: 'POSIX', category: 'Memory & Code', plain: 'POSIX dynamic library loading, threading, or memory mapping' },
  { pattern: /android\.permission\.[A-Z0-9_]+/g, dll: 'ANDROID', category: 'Android Permissions & Components', plain: 'Declares or checks an Android system permission' },
];

function populateFallbackIndicators(strings, headerBuf, imports, capabilityMap) {
  const seenFns = new Set(imports.map((i) => `${i.dll}!${i.function}`));
  const textCorpus = strings.map((s) => s.value).join('\n');

  for (const [apiName, meta] of Object.entries(API_DICTIONARY)) {
    if (seenFns.has(`RUNTIME!${apiName}`)) continue;
    const hit = textCorpus.includes(apiName) || headerBuf.includes(Buffer.from(apiName, 'ascii'));
    if (hit) {
      seenFns.add(`RUNTIME!${apiName}`);
      imports.push({
        dll: 'DETECTED_SYMBOL',
        function: apiName,
        address: 'N/A',
        category: meta.category,
        plain: meta.plain,
        signature: meta.sig,
      });
    }
  }

  for (const rule of RUNTIME_INDICATOR_RULES) {
    const matches = textCorpus.match(rule.pattern);
    if (matches) {
      for (const m of new Set(matches)) {
        const key = `${rule.dll}!${m}`;
        if (seenFns.has(key)) continue;
        seenFns.add(key);
        imports.push({
          dll: rule.dll,
          function: m,
          address: 'N/A',
          category: rule.category,
          plain: rule.plain,
          signature: `${m}(...)`,
        });
      }
    }
  }

  const urlCount = strings.filter((s) => s.section === 'Web Link / URL').length;
  if (urlCount > 0 && !capabilityMap.has('Internet & Network')) {
    capabilityMap.set('Internet & Network', [`References ${urlCount} embedded URL(s) or server endpoint(s)`]);
  }
}

function analyzeElfTarget(fd, fileSize, headerBuf, filePath) {
  const eiClass = headerBuf[4];
  const isLE = headerBuf[5] !== 2;
  const is64 = eiClass === 2;
  const readU16 = (b, o) => (isLE ? b.readUInt16LE(o) : b.readUInt16BE(o));
  const readU32 = (b, o) => (isLE ? b.readUInt32LE(o) : b.readUInt32BE(o));
  const readU64 = (b, o) => (isLE ? b.readBigUInt64LE(o) : b.readBigUInt64BE(o));

  const eType = readU16(headerBuf, 16);
  const eMachine = readU16(headerBuf, 18);
  const machineNames = {
    0x3e: '64-bit Intel/AMD (x86_64)',
    0x03: '32-bit Intel/AMD (x86)',
    0xb7: '64-bit ARM (AArch64)',
    0x28: '32-bit ARM',
    0xf3: 'RISC-V',
    0x08: 'MIPS',
  };
  const arch = machineNames[eMachine] || `ELF Machine 0x${eMachine.toString(16).toUpperCase()}`;
  const format = is64 ? 'ELF64' : 'ELF32';
  const plainFormat = eType === 3 ? 'Linux Shared Library / PIE Executable (ELF)' : 'Linux Executable Binary (ELF)';
  const subsystem = 'Linux / POSIX Runtime';

  const eEntry = is64 ? readU64(headerBuf, 24) : BigInt(readU32(headerBuf, 24));
  const eShoff = is64 ? Number(readU64(headerBuf, 40)) : readU32(headerBuf, 32);
  const eShentsize = readU16(headerBuf, is64 ? 58 : 46);
  const eShnum = readU16(headerBuf, is64 ? 60 : 48);
  const eShstrndx = readU16(headerBuf, is64 ? 62 : 50);

  const sections = [];
  if (eShoff > 0 && eShentsize > 0 && eShnum > 0 && eShnum < 128) {
    const shTableBuf = readFileSlice(fd, fileSize, eShoff, eShentsize * eShnum);
    let shstrBuf = Buffer.alloc(0);
    if (eShstrndx < eShnum && (eShstrndx + 1) * eShentsize <= shTableBuf.length) {
      const strBase = eShstrndx * eShentsize;
      const strOff = is64 ? Number(readU64(shTableBuf, strBase + 24)) : readU32(shTableBuf, strBase + 16);
      const strSize = is64 ? Number(readU64(shTableBuf, strBase + 32)) : readU32(shTableBuf, strBase + 20);
      if (strSize > 0 && strSize < 1024 * 1024) {
        shstrBuf = readFileSlice(fd, fileSize, strOff, strSize);
      }
    }

    for (let i = 0; i < eShnum; i++) {
      const off = i * eShentsize;
      if (off + eShentsize > shTableBuf.length) break;
      const nameOff = readU32(shTableBuf, off);
      let secName = `sec_${i}`;
      if (nameOff < shstrBuf.length) {
        let end = nameOff;
        while (end < shstrBuf.length && shstrBuf[end] !== 0) end++;
        secName = shstrBuf.toString('ascii', nameOff, end) || secName;
      }
      const shAddr = is64 ? readU64(shTableBuf, off + 16) : BigInt(readU32(shTableBuf, off + 12));
      const shOffset = is64 ? Number(readU64(shTableBuf, off + 24)) : readU32(shTableBuf, off + 16);
      const shSize = is64 ? Number(readU64(shTableBuf, off + 32)) : readU32(shTableBuf, off + 20);
      if (secName || shSize > 0) {
        sections.push({
          name: secName,
          vAddr: Number(shAddr & 0xffffffffn),
          vSize: shSize,
          rawPtr: shOffset,
          rawSize: shSize,
          address: formatHex64(shAddr),
          size: shSize,
        });
      }
    }
  }

  const scanBuf = fileSize > headerBuf.length
    ? readFileSlice(fd, fileSize, 0, Math.min(fileSize, 8 * 1024 * 1024))
    : headerBuf;
  const strings = extractStringsFromBuffer(scanBuf, 0, 1200);
  const functions = [];

  if (eMachine === 0x3e && eEntry > 0n) {
    let entryFileOff = -1;
    const textSec = sections.find((s) => s.name === '.text') || sections.find((s) => {
      const va = BigInt(s.address);
      return eEntry >= va && eEntry < va + BigInt(s.size || 0);
    });
    if (textSec) {
      const va = BigInt(textSec.address);
      if (eEntry >= va && eEntry < va + BigInt(textSec.size || 0)) {
        entryFileOff = textSec.rawPtr + Number(eEntry - va);
      }
    } else if (eEntry < BigInt(fileSize)) {
      entryFileOff = Number(eEntry);
    }

    if (entryFileOff >= 0 && entryFileOff < fileSize) {
      const codeBuf = readFileSlice(fd, fileSize, entryFileOff, 512);
      const disasm = disassembleX64Buffer(codeBuf, eEntry, 140, {});
      const addrHex = formatHex64(eEntry);
      const sig = 'uint64_t entry(uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx)';
      const decompiled = decompileInstructionsToC(
        {
          name: 'entry',
          address: addrHex,
          size: codeBuf.length,
          signature: sig,
          plainTitle: 'ELF Entry Point (_start)',
          plainExplanation: `Primary ELF entry point of ${path.basename(filePath)} at ${addrHex}.`,
        },
        disasm
      );
      functions.push({
        address: addrHex,
        rva: Number(eEntry),
        name: 'entry',
        size: codeBuf.length,
        calls: disasm.filter((d) => d.mnemonic === 'call').length,
        category: 'Entry Point',
        signature: sig,
        plainTitle: 'ELF Entry Point (_start)',
        plainExplanation: `Primary ELF entry point of ${path.basename(filePath)} at ${addrHex}.`,
        disassembly: disasm,
        decompiled,
      });
    }
  }

  return {
    format,
    plainFormat,
    arch,
    subsystem,
    entryPointHex: formatHex64(eEntry),
    imageBaseHex: '0x0',
    securityFeatures: ['ELF Header Parsed', is64 ? '64-bit Address Space' : '32-bit Address Space'],
    sections,
    functions,
    strings,
    extraCapabilities: [],
  };
}

function analyzeMachOTarget(fd, fileSize, headerBuf) {
  const magicBE = headerBuf.readUInt32BE(0);
  const magicLE = headerBuf.readUInt32LE(0);
  const isFat = magicBE === 0xcafebabe;
  const is64 = magicBE === 0xfeedfacf || magicLE === 0xfeedfacf;
  const isLE = magicLE === 0xfeedface || magicLE === 0xfeedfacf;

  let arch = 'Apple Binary';
  if (isFat) {
    const nFatArch = headerBuf.readUInt32BE(4);
    arch = `Universal Fat Binary (${nFatArch} slice${nFatArch === 1 ? '' : 's'})`;
  } else {
    const cpuType = isLE ? headerBuf.readUInt32LE(4) : headerBuf.readUInt32BE(4);
    if (cpuType === 0x01000007) arch = '64-bit Intel (x86_64)';
    else if (cpuType === 0x00000007) arch = '32-bit Intel (x86)';
    else if (cpuType === 0x0100000c) arch = '64-bit Apple Silicon (ARM64)';
    else if (cpuType === 0x0000000c) arch = '32-bit ARM';
  }

  const scanBuf = fileSize > headerBuf.length
    ? readFileSlice(fd, fileSize, 0, Math.min(fileSize, 8 * 1024 * 1024))
    : headerBuf;
  const strings = extractStringsFromBuffer(scanBuf, 0, 1200);

  return {
    format: isFat ? 'Mach-O Universal' : is64 ? 'Mach-O 64-bit' : 'Mach-O 32-bit',
    plainFormat: 'macOS / iOS Mach-O Executable or Library',
    arch,
    subsystem: 'macOS / iOS Darwin',
    entryPointHex: '0x0',
    imageBaseHex: '0x100000000',
    securityFeatures: ['Mach-O Header Parsed'],
    sections: [],
    functions: [],
    strings,
    extraCapabilities: [],
  };
}

function analyzeAsarTarget(fd, fileSize, headerBuf, filePath) {
  if (headerBuf.length < 16) return null;
  const sizePickle = headerBuf.readUInt32LE(0);
  const headerSize = headerBuf.readUInt32LE(4);
  const jsonLen = headerBuf.readUInt32LE(12);
  if (sizePickle !== 4 || headerSize < 12 || jsonLen === 0 || 8 + headerSize > fileSize || jsonLen > 32 * 1024 * 1024) {
    return null;
  }

  const actualJsonLen = Math.min(jsonLen, Math.max(0, headerSize - 8));
  if (actualJsonLen === 0) return null;
  const fullHdrBuf = 16 + actualJsonLen <= headerBuf.length
    ? headerBuf.subarray(16, 16 + actualJsonLen)
    : readFileSlice(fd, fileSize, 16, actualJsonLen);
  const jsonStr = fullHdrBuf.toString('utf8').replace(/\0+$/, '');
  let tree = null;
  try {
    tree = JSON.parse(jsonStr);
  } catch (_) {
    for (let k = 1; k <= 4; k++) {
      try {
        tree = JSON.parse(jsonStr + '}'.repeat(k));
        break;
      } catch (__) {}
    }
  }
  if (!tree || typeof tree !== 'object' || !tree.files) return null;

  const dataBaseOffset = 8 + headerSize;
  const entries = [];
  const topDirs = new Map();
  let totalFiles = 0;

  const walk = (node, prefix) => {
    if (!node || !node.files) return;
    for (const [name, child] of Object.entries(node.files)) {
      const relPath = prefix ? `${prefix}/${name}` : name;
      if (child.files) {
        walk(child, relPath);
      } else {
        totalFiles++;
        const top = relPath.includes('/') ? relPath.split('/')[0] : '(root)';
        const size = Number(child.size || 0);
        const offset = child.offset !== undefined ? Number(child.offset) : -1;
        const prev = topDirs.get(top) || { count: 0, size: 0 };
        topDirs.set(top, { count: prev.count + 1, size: prev.size + size });
        if (entries.length < 400) {
          entries.push({ relPath, size, offset, unpacked: Boolean(child.unpacked) });
        }
      }
    }
  };
  walk(tree, '');

  const sections = Array.from(topDirs.entries()).map(([dirName, info], idx) => ({
    name: dirName,
    vAddr: idx,
    vSize: info.size,
    rawPtr: dataBaseOffset,
    rawSize: info.size,
    address: `${info.count} file(s)`,
    size: info.size,
  }));

  const functions = [];
  const pkgEntry = entries.find((e) => e.relPath === 'package.json' && e.offset >= 0 && e.size > 0 && e.size < 512 * 1024);
  let pkgMain = '';
  let pkgSummary = '';
  if (pkgEntry) {
    const pkgBuf = readFileSlice(fd, fileSize, dataBaseOffset + pkgEntry.offset, pkgEntry.size);
    const pkgText = pkgBuf.toString('utf8');
    try {
      const pkgJson = JSON.parse(pkgText);
      pkgMain = pkgJson.main || '';
      pkgSummary = `App "${pkgJson.name || path.basename(filePath)}" v${pkgJson.version || '?'} (main: ${pkgMain || 'index.js'})`;
    } catch (_) {}
    functions.push({
      address: `0x${(dataBaseOffset + pkgEntry.offset).toString(16).toUpperCase()}`,
      rva: dataBaseOffset + pkgEntry.offset,
      name: 'package.json',
      size: pkgEntry.size,
      calls: 0,
      category: 'ASAR Manifest',
      signature: 'package.json (Electron App Manifest)',
      plainTitle: 'Electron Package Manifest',
      plainExplanation: pkgSummary || 'Root Electron package.json defining entry point, dependencies, and scripts.',
      disassembly: [],
      decompiled: pkgText,
    });
  }

  const keyCodeEntries = entries
    .filter((e) => !e.unpacked && e.offset >= 0 && e.size > 0 && /\.(js|cjs|mjs|ts|json|html)$/i.test(e.relPath) && e.relPath !== 'package.json')
    .sort((a, b) => {
      const score = (p) => {
        if (pkgMain && (p === pkgMain || p === pkgMain.replace(/^\.\//, ''))) return 0;
        if (/preload|main|index|ipc/i.test(p)) return 1;
        return 2;
      };
      return score(a.relPath) - score(b.relPath);
    })
    .slice(0, 20);

  for (const entry of keyCodeEntries) {
    const raw = readFileSlice(fd, fileSize, dataBaseOffset + entry.offset, Math.min(entry.size, 32768));
    functions.push({
      address: `0x${(dataBaseOffset + entry.offset).toString(16).toUpperCase()}`,
      rva: dataBaseOffset + entry.offset,
      name: entry.relPath,
      size: entry.size,
      calls: 0,
      category: 'ASAR Module',
      signature: `// ASAR Entry: ${entry.relPath} (${entry.size} bytes)`,
      plainTitle: `Packaged Source/Asset (${entry.relPath})`,
      plainExplanation: `Embedded file at ASAR offset 0x${(dataBaseOffset + entry.offset).toString(16).toUpperCase()} (${entry.size.toLocaleString()} bytes).`,
      disassembly: [],
      decompiled: raw.toString('utf8'),
    });
  }

  const scanBuf = fileSize > headerBuf.length
    ? readFileSlice(fd, fileSize, 0, Math.min(fileSize, 8 * 1024 * 1024))
    : headerBuf;
  const strings = extractStringsFromBuffer(scanBuf, 0, 1200);
  const exportsList = entries.slice(0, 120).map((e) => ({
    name: e.relPath,
    rva: e.offset >= 0 ? dataBaseOffset + e.offset : 0,
    address: e.offset >= 0 ? `0x${(dataBaseOffset + e.offset).toString(16).toUpperCase()}` : 'unpacked',
  }));

  const nativeAddons = entries.filter((e) => /\.node$|\.dll$|\.exe$/i.test(e.relPath)).map((e) => e.relPath);
  const extraCapabilities = [
    {
      title: 'Electron ASAR Archive Structure',
      count: totalFiles,
      examples: [
        `Contains ${totalFiles.toLocaleString()} packaged files across ${topDirs.size} top-level folder(s)`,
        ...(pkgSummary ? [pkgSummary] : []),
        ...(nativeAddons.length > 0 ? [`Native addons/binaries: ${nativeAddons.slice(0, 5).join(', ')}`] : []),
      ],
    },
  ];

  return {
    format: 'Electron ASAR Archive',
    plainFormat: 'Electron Desktop Application Bundle (.asar)',
    arch: 'JavaScript / Node.js / Chromium',
    subsystem: 'Electron Desktop Runtime',
    entryPointHex: pkgMain || 'package.json',
    imageBaseHex: `0x${dataBaseOffset.toString(16).toUpperCase()}`,
    securityFeatures: ['ASAR Pickle JSON Index', `Data Offset 0x${dataBaseOffset.toString(16).toUpperCase()}`],
    sections,
    functions,
    strings,
    exportsList,
    totalFunctionCount: totalFiles,
    extraCapabilities,
  };
}

function analyzeZipPackageTarget(fd, fileSize, headerBuf, filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const formatMap = {
    '.apk': ['Android Package (APK)', 'Android Mobile Application (.apk)', 'Dalvik / ART Bytecode & Native JNI', 'Android OS'],
    '.msix': ['Windows App Package (MSIX)', 'Windows Modern MSIX Package (.msix)', 'Windows AppContainer', 'Windows AppContainer'],
    '.appx': ['Windows App Package (APPX)', 'Windows Modern AppX Package (.appx)', 'Windows AppContainer', 'Windows AppContainer'],
    '.jar': ['Java Archive (JAR)', 'Java Bytecode Archive (.jar)', 'JVM Bytecode', 'Java Virtual Machine'],
    '.ipa': ['iOS App Archive (IPA)', 'Apple iOS Application Package (.ipa)', 'iOS ARM64 Bundle', 'Apple iOS'],
  };
  const [format, plainFormat, arch, subsystem] = formatMap[ext] || [
    'ZIP Archive / Package',
    'Compressed ZIP Application Package (.zip)',
    'Cross-Platform Archive',
    'Packaged Container',
  ];

  const entries = [];
  const tailSize = Math.min(fileSize, 65557);
  const tailBuf = readFileSlice(fd, fileSize, fileSize - tailSize, tailSize);
  let cdOffset = -1;
  let cdSize = 0;
  for (let i = tailBuf.length - 22; i >= 0; i--) {
    if (tailBuf.readUInt32LE(i) === 0x06054b50) {
      cdSize = tailBuf.readUInt32LE(i + 12);
      cdOffset = tailBuf.readUInt32LE(i + 16);
      break;
    }
  }

  if (cdOffset >= 0 && cdSize > 0 && cdOffset < fileSize) {
    const cdBuf = readFileSlice(fd, fileSize, cdOffset, Math.min(cdSize, 4 * 1024 * 1024));
    let pos = 0;
    while (pos + 46 <= cdBuf.length && entries.length < 600) {
      if (cdBuf.readUInt32LE(pos) !== 0x02014b50) break;
      const compSize = cdBuf.readUInt32LE(pos + 20);
      const uncompSize = cdBuf.readUInt32LE(pos + 24);
      const fnLen = cdBuf.readUInt16LE(pos + 28);
      const extraLen = cdBuf.readUInt16LE(pos + 30);
      const commentLen = cdBuf.readUInt16LE(pos + 32);
      const localHdrOff = cdBuf.readUInt32LE(pos + 42);
      if (pos + 46 + fnLen > cdBuf.length) break;
      const name = cdBuf.toString('utf8', pos + 46, pos + 46 + fnLen);
      entries.push({ name, compSize, uncompSize, localHdrOff });
      pos += 46 + fnLen + extraLen + commentLen;
    }
  } else {
    let pos = 0;
    while (pos + 30 <= headerBuf.length && entries.length < 300) {
      if (headerBuf.readUInt32LE(pos) !== 0x04034b50) break;
      const compSize = headerBuf.readUInt32LE(pos + 18);
      const uncompSize = headerBuf.readUInt32LE(pos + 22);
      const fnLen = headerBuf.readUInt16LE(pos + 26);
      const extraLen = headerBuf.readUInt16LE(pos + 28);
      if (pos + 30 + fnLen > headerBuf.length) break;
      const name = headerBuf.toString('utf8', pos + 30, pos + 30 + fnLen);
      entries.push({ name, compSize, uncompSize, localHdrOff: pos });
      pos += 30 + fnLen + extraLen + compSize;
      if (compSize === 0) break;
    }
  }

  const groupBuckets = new Map();
  for (const e of entries) {
    const bucket = e.name.includes('/') ? e.name.split('/')[0] : '(root)';
    const cur = groupBuckets.get(bucket) || { count: 0, size: 0, offset: e.localHdrOff };
    groupBuckets.set(bucket, {
      count: cur.count + 1,
      size: cur.size + (e.uncompSize || e.compSize || 0),
      offset: Math.min(cur.offset, e.localHdrOff),
    });
  }

  const sections = Array.from(groupBuckets.entries()).map(([bucket, info]) => ({
    name: bucket,
    vAddr: info.offset,
    vSize: info.size,
    rawPtr: info.offset,
    rawSize: info.size,
    address: `${info.count} member(s)`,
    size: info.size,
  }));

  const exportsList = entries.slice(0, 120).map((e) => ({
    name: e.name,
    rva: e.localHdrOff,
    address: `0x${e.localHdrOff.toString(16).toUpperCase()}`,
  }));

  const scanBuf = fileSize > headerBuf.length
    ? readFileSlice(fd, fileSize, 0, Math.min(fileSize, 8 * 1024 * 1024))
    : headerBuf;
  const strings = extractStringsFromBuffer(scanBuf, 0, 1200);

  const keyEntries = entries
    .filter((e) => /AndroidManifest\.xml$|classes\d*\.dex$|\.so$|\.dll$|\.exe$|AppxManifest\.xml$|META-INF\/MANIFEST\.MF$/i.test(e.name))
    .slice(0, 16);
  const functions = keyEntries.map((e) => ({
    address: `0x${e.localHdrOff.toString(16).toUpperCase()}`,
    rva: e.localHdrOff,
    name: e.name,
    size: e.uncompSize || e.compSize || 0,
    calls: 0,
    category: 'Package Member',
    signature: `// ZIP Member: ${e.name} (uncompressed ${e.uncompSize} B, compressed ${e.compSize} B)`,
    plainTitle: `Archive Entry (${e.name})`,
    plainExplanation: `Packaged member at local header offset 0x${e.localHdrOff.toString(16).toUpperCase()}.`,
    disassembly: [],
    decompiled: `// Archive Member: ${e.name}\n// Local Header Offset: 0x${e.localHdrOff.toString(16).toUpperCase()}\n// Compressed Size: ${e.compSize} bytes\n// Uncompressed Size: ${e.uncompSize} bytes\n`,
  }));

  const extraCapabilities = [];
  if (entries.length > 0) {
    extraCapabilities.push({
      title: 'Archive Package Inventory',
      count: entries.length,
      examples: entries.slice(0, 6).map((e) => `${e.name} (${(e.uncompSize || 0).toLocaleString()} bytes)`),
    });
  }

  return {
    format,
    plainFormat,
    arch,
    subsystem,
    entryPointHex: keyEntries[0]?.name || '0x0',
    imageBaseHex: '0x0',
    securityFeatures: ['ZIP Central Directory Parsed'],
    sections,
    functions,
    strings,
    exportsList,
    totalFunctionCount: entries.length,
    extraCapabilities,
  };
}

function readUleb128(buf, pos) {
  let result = 0;
  let shift = 0;
  let cursor = pos;
  while (cursor < buf.length && shift <= 35) {
    const byte = buf[cursor++];
    result |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7;
  }
  return { value: result >>> 0, next: cursor };
}

function analyzeWasmTarget(fd, fileSize, headerBuf) {
  const fullBuf = fileSize <= 16 * 1024 * 1024
    ? readFileSlice(fd, fileSize, 0, fileSize)
    : headerBuf;
  const version = fullBuf.length >= 8 ? fullBuf.readUInt32LE(4) : 1;
  const secNames = {
    0: 'custom',
    1: 'type',
    2: 'import',
    3: 'function',
    4: 'table',
    5: 'memory',
    6: 'global',
    7: 'export',
    8: 'start',
    9: 'element',
    10: 'code',
    11: 'data',
    12: 'datacount',
  };

  const sections = [];
  const exportsList = [];
  const imports = [];
  let pos = 8;
  while (pos < fullBuf.length) {
    const secId = fullBuf[pos++];
    const lenRes = readUleb128(fullBuf, pos);
    pos = lenRes.next;
    const secSize = lenRes.value;
    const secEnd = Math.min(fullBuf.length, pos + secSize);
    const secName = secNames[secId] || `section_${secId}`;
    sections.push({
      name: secName,
      vAddr: pos,
      vSize: secSize,
      rawPtr: pos,
      rawSize: secSize,
      address: `0x${pos.toString(16).toUpperCase()}`,
      size: secSize,
    });

    if (secId === 7 && pos < secEnd) {
      let c = readUleb128(fullBuf, pos);
      let p = c.next;
      for (let i = 0; i < Math.min(c.value, 200) && p < secEnd; i++) {
        const nl = readUleb128(fullBuf, p);
        p = nl.next;
        const name = fullBuf.toString('utf8', p, Math.min(secEnd, p + nl.value));
        p += nl.value;
        const kind = fullBuf[p++];
        const idx = readUleb128(fullBuf, p);
        p = idx.next;
        if (name) {
          exportsList.push({
            name: `${name} (kind=${kind}, idx=${idx.value})`,
            rva: pos,
            address: `wasm:export#${idx.value}`,
          });
        }
      }
    } else if (secId === 2 && pos < secEnd) {
      let c = readUleb128(fullBuf, pos);
      let p = c.next;
      for (let i = 0; i < Math.min(c.value, 200) && p < secEnd; i++) {
        const ml = readUleb128(fullBuf, p);
        p = ml.next;
        const modName = fullBuf.toString('utf8', p, Math.min(secEnd, p + ml.value));
        p += ml.value;
        const fl = readUleb128(fullBuf, p);
        p = fl.next;
        const fieldName = fullBuf.toString('utf8', p, Math.min(secEnd, p + fl.value));
        p += fl.value;
        const kind = fullBuf[p++];
        if (kind === 0) {
          p = readUleb128(fullBuf, p).next;
        } else if (kind === 1) {
          p += 1;
          const limFlag = fullBuf[p++];
          p = readUleb128(fullBuf, p).next;
          if (limFlag & 1) p = readUleb128(fullBuf, p).next;
        } else if (kind === 2) {
          const limFlag = fullBuf[p++];
          p = readUleb128(fullBuf, p).next;
          if (limFlag & 1) p = readUleb128(fullBuf, p).next;
        } else if (kind === 3) {
          p += 2;
        }
        if (modName || fieldName) {
          imports.push({
            dll: modName || 'env',
            function: fieldName || 'import',
            address: `wasm:import#${i}`,
            category: 'WASM Import',
            plain: `WebAssembly import ${modName}.${fieldName} (kind ${kind})`,
            signature: `${modName}.${fieldName}(...)`,
          });
        }
      }
    }
    pos = secEnd;
  }

  const strings = extractStringsFromBuffer(fullBuf, 0, 1200);
  return {
    format: `WebAssembly (WASM v${version})`,
    plainFormat: 'WebAssembly Binary Module (.wasm)',
    arch: 'WebAssembly Stack VM (wasm32/64)',
    subsystem: 'Browser / WASI Runtime',
    entryPointHex: exportsList[0]?.address || '0x8',
    imageBaseHex: '0x0',
    securityFeatures: ['WASM Sandboxed Linear Memory'],
    sections,
    functions: [],
    strings,
    exportsList,
    imports,
    extraCapabilities: [],
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
    const { sha256, md5 } = computeFileHashes(fd, fileSize, headerBuf);

    let format = 'Binary / Data File';
    let plainFormat = 'General Application or Data File';
    let arch = 'Unknown';
    let subsystem = 'Desktop / System';
    let compileDate = new Date(stats.mtimeMs).toLocaleDateString();
    let imageBase = 0x140000000n;
    let entryRva = 0;
    let is64Bit = true;
    let imageBaseOverride = null;
    let entryPointOverride = null;
    let extraCapabilities = [];

    const sections = [];
    const securityFeatures = [];
    const imports = [];
    const exportsList = [];
    const functions = [];
    const iatMap = new Map();
    const funcMap = new Map();
    let strings = [];
    let totalFunctionCount = 0;

    // Check if Windows PE ('MZ' + 'PE\0\0')
    let isValidPE = false;
    if (headerBuf.length >= 64 && headerBuf[0] === 0x4d && headerBuf[1] === 0x5a) {
      const peOffset = headerBuf.readUInt32LE(0x3c);
      if (peOffset > 0 && peOffset + 24 < headerBuf.length && headerBuf.toString('ascii', peOffset, peOffset + 4) === 'PE\0\0') {
        isValidPE = true;
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
    }

    if (!isValidPE) {
      let parsed = null;
      const ext = path.extname(filePath).toLowerCase();

      if (headerBuf.length >= 64 && headerBuf[0] === 0x7f && headerBuf[1] === 0x45 && headerBuf[2] === 0x4c && headerBuf[3] === 0x46) {
        parsed = analyzeElfTarget(fd, fileSize, headerBuf, filePath);
      } else if (headerBuf.length >= 8 && headerBuf[0] === 0x00 && headerBuf[1] === 0x61 && headerBuf[2] === 0x73 && headerBuf[3] === 0x6d) {
        parsed = analyzeWasmTarget(fd, fileSize, headerBuf);
      } else if (headerBuf.length >= 4 && headerBuf[0] === 0x50 && headerBuf[1] === 0x4b && headerBuf[2] === 0x03 && headerBuf[3] === 0x04) {
        parsed = analyzeZipPackageTarget(fd, fileSize, headerBuf, filePath);
      } else if (ext === '.asar' || (headerBuf.length >= 17 && headerBuf.readUInt32LE(0) === 4 && headerBuf[16] === 0x7b)) {
        parsed = analyzeAsarTarget(fd, fileSize, headerBuf, filePath);
      } else if (headerBuf.length >= 8) {
        const mBE = headerBuf.readUInt32BE(0);
        const mLE = headerBuf.readUInt32LE(0);
        const isFatMachO = mBE === 0xcafebabe && headerBuf.readUInt32BE(4) > 0 && headerBuf.readUInt32BE(4) <= 32;
        if (mBE === 0xfeedface || mBE === 0xfeedfacf || mLE === 0xfeedface || mLE === 0xfeedfacf || isFatMachO) {
          parsed = analyzeMachOTarget(fd, fileSize, headerBuf);
        }
      }

      if (parsed) {
        format = parsed.format;
        plainFormat = parsed.plainFormat;
        arch = parsed.arch;
        subsystem = parsed.subsystem;
        imageBaseOverride = parsed.imageBaseHex;
        entryPointOverride = parsed.entryPointHex;
        if (parsed.securityFeatures) securityFeatures.push(...parsed.securityFeatures);
        if (parsed.sections) sections.push(...parsed.sections);
        if (parsed.functions) functions.push(...parsed.functions);
        if (parsed.strings) strings = parsed.strings;
        if (parsed.exportsList) exportsList.push(...parsed.exportsList);
        if (parsed.imports) imports.push(...parsed.imports);
        if (parsed.totalFunctionCount) totalFunctionCount = parsed.totalFunctionCount;
        if (parsed.extraCapabilities) extraCapabilities = parsed.extraCapabilities;
      } else {
        const scanBuf = fileSize > headerBuf.length
          ? readFileSlice(fd, fileSize, 0, Math.min(fileSize, 8 * 1024 * 1024))
          : headerBuf;
        strings = extractStringsFromBuffer(scanBuf, 0, 1200);
        imageBaseOverride = '0x0';
        entryPointOverride = '0x0';
      }
    }

    // Build Plain-English Capability Cards from real parsed imports & sections
    const capabilityMap = new Map();
    if (imports.length === 0) {
      populateFallbackIndicators(strings, headerBuf, imports, capabilityMap);
    }

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

    const capabilities = [
      ...extraCapabilities,
      ...Array.from(capabilityMap.entries()).map(([title, items]) => ({
        title,
        count: items.length,
        examples: items.slice(0, 6),
      })),
    ];

    const isPacked = entropy >= 7.25;
    const packingExplanation = isPacked
      ? `High entropy (${entropy}/8.0). Significant portions of this binary or package are compressed, packed, or encrypted.`
      : `Unpacked / readable structure (Entropy ${entropy}/8.0). ${imports.length} API/indicator signals across ${new Set(imports.map((i) => i.dll)).size} module(s) and ${totalFunctionCount || functions.length} discovered routines/entries are directly inspectable.`;

    const fileSizeFormatted =
      fileSize > 1024 * 1024
        ? `${(fileSize / (1024 * 1024)).toFixed(2)} MB`
        : `${(fileSize / 1024).toFixed(1)} KB`;

    return {
      success: true,
      inspectedAt: new Date().toISOString(),
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
        imageBase: imageBaseOverride || formatHex64(imageBase),
        entryPoint: entryPointOverride || formatHex64(imageBase + BigInt(entryRva)),
        totalFunctionsDiscovered: totalFunctionCount || functions.length,
        totalDllsImported: new Set(imports.map((i) => i.dll)).size,
        entropy,
        isPacked,
        packingExplanation,
        securityFeatures: securityFeatures.length > 0 ? securityFeatures : ['Standard File Header'],
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

function escapeMdCell(val) {
  return String(val == null ? '' : val)
    .replace(/\r?\n/g, ' ')
    .replace(/\|/g, '\\|');
}

function describeSectionPurpose(secName) {
  const name = String(secName || '');
  if (name === '.text') return 'Executable x86_64 machine code';
  if (name === '.rdata' || name === '.rodata') return 'Read-only constants, strings, and import/export tables';
  if (name === '.data') return 'Initialized global and static variables';
  if (name === '.pdata') return 'x64 exception unwind table (maps every function boundary)';
  if (name === '.rsrc') return 'Embedded resources (UI skins, icons, audio, manifests)';
  if (name.toLowerCase().includes('nv')) return 'NVIDIA CUDA GPU compute kernels (AI / neural DSP)';
  if (name === '.reloc') return 'ASLR base relocation table';
  if (name === '.idata') return 'Import directory / IAT bindings';
  if (name === '.edata') return 'Export directory table';
  return 'Application data / runtime section or package group';
}

/**
 * Generates a comprehensive, self-contained Markdown reverse-engineering report
 * formatted for immediate ingestion by Antigravity AI coding/security agents.
 */
function generateAntigravityReport(analysisData, options = {}) {
  const data = analysisData || {};
  const target = data.target || {};
  const functions = Array.isArray(data.functions) ? data.functions : [];
  const imports = Array.isArray(data.imports) ? data.imports : [];
  const strings = Array.isArray(data.strings) ? data.strings : [];

  const includeAll = Boolean(options.includeAllDecompiled);
  const maxFunctionsInTable = options.maxFunctionsInTable || (includeAll ? functions.length || 500 : 80);
  const maxDecompiledFunctions = options.maxDecompiledFunctions || (includeAll ? functions.length || 500 : 15);
  const maxImports = options.maxImports || (includeAll ? imports.length || 5000 : 200);
  const maxStringsPerCategory = options.maxStringsPerCategory || (includeAll ? 250 : 50);

  const inspectedAt = data.inspectedAt || new Date().toISOString();
  const targetName = target.name || 'unknown-target';
  const lines = [];

  // Antigravity AI Ingestion Header
  lines.push(`# 🛡️ AegisRE Full Reverse-Engineering Report: ${targetName}`);
  lines.push('');
  lines.push('> **Antigravity AI Context Header**');
  lines.push(`> - **Target**: \`${targetName}\` (\`${target.path || 'unknown'}\`)`);
  lines.push(`> - **Format / Arch**: ${target.format || 'Unknown'} | ${target.arch || 'Unknown'} | ${target.subsystem || 'Unknown'}`);
  lines.push(`> - **Inspected At**: \`${inspectedAt}\``);
  lines.push(`> - **SHA-256**: \`${target.hashes?.sha256 || 'N/A'}\``);
  if (data.savedReportPath || data.antigravityReportPath) {
    lines.push(`> - **Report File**: \`${data.savedReportPath || data.antigravityReportPath}\``);
  }
  lines.push('');
  lines.push(
    'All facts below are static observations extracted directly from the shipped binary or package (file headers, section tables, import/export directories, `.pdata` function unwind table, x86_64 disassembly, Ghidra-style C pseudocode lifting, and encoded strings). Treat inferred plain-English labels and lifted C pseudocode as static reconstructions requiring verification against live execution if needed.'
  );
  lines.push('');

  // Section 1 — Target Identity, Security Mitigations & Cryptographic Evidence
  lines.push('## 1. Target Identity, Security Mitigations & Cryptographic Evidence');
  lines.push('');
  lines.push('| Property | Observed Value |');
  lines.push('| :--- | :--- |');
  lines.push(`| File Name | \`${escapeMdCell(targetName)}\` |`);
  lines.push(`| Full Path | \`${escapeMdCell(target.path || 'N/A')}\` |`);
  lines.push(`| Format | ${escapeMdCell(target.format || 'Unknown')} |`);
  lines.push(`| Plain Description | ${escapeMdCell(target.plainFormat || target.format || 'Unknown')} |`);
  lines.push(`| Architecture | ${escapeMdCell(target.arch || 'Unknown')} |`);
  lines.push(`| Subsystem / Runtime | ${escapeMdCell(target.subsystem || 'Unknown')} |`);
  lines.push(`| File Size | ${escapeMdCell(target.sizeFormatted || `${target.size || 0} B`)} (${Number(target.size || 0).toLocaleString()} bytes) |`);
  lines.push(`| Compile / Modified Date | ${escapeMdCell(target.compileDate || 'N/A')} |`);
  lines.push(`| Image Base | \`${escapeMdCell(target.imageBase || '0x0')}\` |`);
  lines.push(`| Entry Point | \`${escapeMdCell(target.entryPoint || '0x0')}\` |`);
  lines.push(`| Discovered Subroutines / Entries | ${Number(target.totalFunctionsDiscovered || functions.length).toLocaleString()} (${functions.length} decoded in workspace) |`);
  lines.push(`| Imported APIs / DLLs | ${imports.length.toLocaleString()} APIs across ${Number(target.totalDllsImported || 0).toLocaleString()} module(s) |`);
  lines.push(`| Entropy & Packing Verdict | ${target.entropy ?? 'N/A'}/8.0 — ${target.isPacked ? '⚠️ Packed / Compressed / Encrypted' : '✅ Unpacked / Directly Inspectable'} |`);
  lines.push(`| Security Mitigations | ${escapeMdCell((target.securityFeatures || ['None detected']).join(', '))} |`);
  lines.push(`| SHA-256 | \`${escapeMdCell(target.hashes?.sha256 || 'N/A')}\` |`);
  lines.push(`| MD5 | \`${escapeMdCell(target.hashes?.md5 || 'N/A')}\` |`);
  lines.push('');

  // Section 2 — Executive Plain-English Architecture & Capabilities
  lines.push('## 2. Executive Plain-English Architecture & Capabilities');
  lines.push('');
  lines.push(target.summary || 'No summary available.');
  lines.push('');
  if (Array.isArray(target.capabilities) && target.capabilities.length > 0) {
    for (const cap of target.capabilities) {
      lines.push(`### ${cap.title} (${cap.count} signal${cap.count === 1 ? '' : 's'})`);
      for (const ex of cap.examples || []) {
        lines.push(`- ${ex}`);
      }
      lines.push('');
    }
  } else {
    lines.push('_No high-level capability groups were derived from imports or embedded indicators._');
    lines.push('');
  }

  // Section 3 — Binary Memory Map / Package Sections & Exported Symbols
  lines.push('## 3. Binary Memory Map / Package Sections & Exported Symbols');
  lines.push('');
  const secDetails = Array.isArray(target.sectionDetails) ? target.sectionDetails : [];
  if (secDetails.length > 0) {
    lines.push(`### Memory & Container Sections (${secDetails.length})`);
    lines.push('');
    lines.push('| Section | Virtual Address / Tag | Virtual Size | Raw File Offset | Raw Size | Purpose |');
    lines.push('| :--- | :--- | ---: | :--- | ---: | :--- |');
    for (const sec of secDetails) {
      lines.push(
        `| \`${escapeMdCell(sec.name)}\` | \`${escapeMdCell(sec.address)}\` | ${Number(sec.vSize ?? sec.size ?? 0).toLocaleString()} B | \`0x${Number(sec.rawPtr || 0).toString(16).toUpperCase()}\` | ${Number(sec.rawSize ?? sec.size ?? 0).toLocaleString()} B | ${escapeMdCell(describeSectionPurpose(sec.name))} |`
      );
    }
    lines.push('');
  } else {
    lines.push('_No section headers parsed for this file format._');
    lines.push('');
  }

  const exportsList = Array.isArray(target.exports) ? target.exports : [];
  if (exportsList.length > 0) {
    const shownExports = includeAll ? exportsList : exportsList.slice(0, 100);
    lines.push(`### Exported Symbols / Package Entries (${exportsList.length} total, showing ${shownExports.length})`);
    lines.push('');
    lines.push('| Symbol / Entry Name | Virtual Address / Offset | RVA |');
    lines.push('| :--- | :--- | :--- |');
    for (const exp of shownExports) {
      lines.push(
        `| \`${escapeMdCell(exp.name)}\` | \`${escapeMdCell(exp.address)}\` | \`0x${Number(exp.rva || 0).toString(16).toUpperCase()}\` |`
      );
    }
    lines.push('');
  }

  // Section 4 — Function Symbol Tree
  lines.push('## 4. Function Symbol Tree');
  lines.push('');
  if (functions.length > 0) {
    const tableFns = functions.slice(0, maxFunctionsInTable);
    lines.push(
      `Showing ${tableFns.length} of ${functions.length} decoded routines (${Number(target.totalFunctionsDiscovered || functions.length).toLocaleString()} total discovered).`
    );
    lines.push('');
    lines.push('| Function Name | Virtual Address | Size (Bytes) | Calls | Category | Description |');
    lines.push('| :--- | :--- | ---: | ---: | :--- | :--- |');
    for (const fn of tableFns) {
      lines.push(
        `| \`${escapeMdCell(fn.name)}\` | \`${escapeMdCell(fn.address)}\` | ${Number(fn.size || 0).toLocaleString()} | ${Number(fn.calls || 0)} | ${escapeMdCell(fn.category || 'Code')} | ${escapeMdCell(fn.plainTitle || fn.plainExplanation || '')} |`
      );
    }
    lines.push('');
  } else {
    lines.push('_No native subroutines decoded for this target._');
    lines.push('');
  }

  // Section 5 — Decompiled C Pseudocode & x86_64 Disassembly (Key Routines)
  lines.push('## 5. Decompiled C Pseudocode & x86_64 Disassembly (Key Routines)');
  lines.push('');
  if (functions.length > 0) {
    const priorityNames = new Set(['entry', 'WinMain', 'main', '__scrt_common_main_seh', '__security_init_cookie', 'package.json']);
    const selectedFns = [];
    const seenAddrs = new Set();

    const addFn = (fn) => {
      if (!fn || selectedFns.length >= maxDecompiledFunctions) return;
      const key = `${fn.address}:${fn.name}`;
      if (seenAddrs.has(key)) return;
      seenAddrs.add(key);
      selectedFns.push(fn);
    };

    for (const fn of functions) {
      if (priorityNames.has(fn.name)) addFn(fn);
    }
    for (const fn of functions) {
      if (fn.category === 'Direct Address Lookup' || fn.category === 'Exported Symbol' || fn.category === 'ASAR Manifest' || fn.category === 'ASAR Module' || fn.category === 'Package Member') {
        addFn(fn);
      }
    }
    for (const fn of functions) {
      addFn(fn);
    }

    lines.push(`Detailed decompilation and instruction trace for ${selectedFns.length} key routine(s):`);
    lines.push('');

    for (const fn of selectedFns) {
      lines.push(`### \`${fn.name}\` (\`${fn.address}\`)`);
      lines.push('');
      lines.push(`- **Size**: ${Number(fn.size || 0).toLocaleString()} bytes | **Calls**: ${Number(fn.calls || 0)} | **Category**: ${fn.category || 'Code'}`);
      if (fn.signature) {
        lines.push(`- **Signature**: \`${fn.signature}\``);
      }
      if (fn.plainExplanation) {
        lines.push(`- **Summary**: ${fn.plainExplanation}`);
      }
      lines.push('');
      if (fn.decompiled) {
        const lang = fn.category === 'ASAR Manifest' ? 'json' : fn.category === 'ASAR Module' ? 'javascript' : 'c';
        lines.push(`\`\`\`${lang}`);
        lines.push(fn.decompiled.trimEnd());
        lines.push('```');
        lines.push('');
      }
      if (Array.isArray(fn.disassembly) && fn.disassembly.length > 0) {
        const insnLimit = includeAll ? fn.disassembly.length : Math.min(fn.disassembly.length, 60);
        lines.push(`**x86_64 Disassembly** (${insnLimit} of ${fn.disassembly.length} decoded instructions):`);
        lines.push('');
        lines.push('```x86asm');
        for (let i = 0; i < insnLimit; i++) {
          const insn = fn.disassembly[i];
          const mnemAndOps = `${insn.mnemonic}${insn.operands ? ' ' + insn.operands : ''}`;
          const cmt = insn.comment ? ` ; ${insn.comment}` : '';
          lines.push(`${insn.address}  ${String(insn.bytes || '').padEnd(24, ' ')}  ${mnemAndOps}${cmt}`);
        }
        if (fn.disassembly.length > insnLimit) {
          lines.push(`; ... (${fn.disassembly.length - insnLimit} additional instructions omitted; enable Exhaustive Mode for full listing)`);
        }
        lines.push('```');
        lines.push('');
      }
    }
  } else {
    lines.push('_No decompiled code or disassembly listings available for this target._');
    lines.push('');
  }

  // Section 6 — Imported DLLs & API Behavioral Matrix
  lines.push('## 6. Imported DLLs & API Behavioral Matrix');
  lines.push('');
  if (imports.length > 0) {
    const dllCounts = new Map();
    for (const imp of imports) {
      const dll = imp.dll || 'UNKNOWN';
      dllCounts.set(dll, (dllCounts.get(dll) || 0) + 1);
    }
    const dllSummary = Array.from(dllCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .map(([dll, count]) => `\`${dll}\` (${count})`)
      .join(', ');
    lines.push(`**Imported Modules (${dllCounts.size}):** ${dllSummary}`);
    lines.push('');

    const prioritizedImports = [...imports].sort((a, b) => {
      const score = (c) => (c && c !== 'System & Runtime' ? 0 : 1);
      return score(a.category) - score(b.category);
    });
    const shownImports = prioritizedImports.slice(0, maxImports);
    lines.push(`Showing ${shownImports.length} of ${imports.length} imported APIs:`);
    lines.push('');
    lines.push('| IAT Address | Module / API | Category | Plain-English Behavior |');
    lines.push('| :--- | :--- | :--- | :--- |');
    for (const imp of shownImports) {
      lines.push(
        `| \`${escapeMdCell(imp.address)}\` | \`${escapeMdCell(imp.dll)}!${escapeMdCell(imp.function)}\` | ${escapeMdCell(imp.category || 'System')} | ${escapeMdCell(imp.plain || '')} |`
      );
    }
    lines.push('');
  } else {
    lines.push('_No imported APIs or runtime indicators detected._');
    lines.push('');
  }

  // Section 7 — Extracted Strings, Endpoints & Engine Clues
  lines.push('## 7. Extracted Strings, Endpoints & Engine Clues');
  lines.push('');
  if (strings.length > 0) {
    const stringCategories = [
      { key: 'Web Link / URL', heading: '🌐 Web Links & Server Endpoints' },
      { key: 'Audio, GPU & Engine Clues', heading: '🎛️ Audio, GPU, Shaders & Engine Clues' },
      { key: 'File Path / System Setting', heading: '📁 File Paths, Registry Keys & Modules' },
      { key: 'Notable Keyword / Command', heading: '🔑 Licensing, Security, Commands & Diagnostics' },
      { key: 'App Text', heading: '📝 Application Text & Identifiers' },
    ];
    for (const cat of stringCategories) {
      const group = strings.filter((s) => s.section === cat.key);
      if (group.length === 0) continue;
      const shown = group.slice(0, maxStringsPerCategory);
      lines.push(`### ${cat.heading} (${group.length} total, showing ${shown.length})`);
      lines.push('');
      lines.push('| Offset | Encoding | Value | Meaning |');
      lines.push('| :--- | :--- | :--- | :--- |');
      for (const s of shown) {
        lines.push(
          `| \`${escapeMdCell(s.offset)}\` | ${escapeMdCell(s.type)} | \`${escapeMdCell(s.value)}\` | ${escapeMdCell(s.plain || '')} |`
        );
      }
      lines.push('');
    }
  } else {
    lines.push('_No readable ASCII or UTF-16LE strings extracted._');
    lines.push('');
  }

  // Section 8 — Header Hex Preview
  lines.push('## 8. Header Hex Preview');
  lines.push('');
  lines.push('```text');
  lines.push(target.hexPreview || 'No hex preview available.');
  lines.push('```');
  lines.push('');

  // Section 9 — Suggested Antigravity Tasks & Follow-Up Prompts
  lines.push('## 9. Suggested Antigravity Tasks & Follow-Up Prompts');
  lines.push('');
  lines.push(`Copy or adapt any of the prompts below when feeding this report into **Antigravity** for \`${targetName}\`:`);
  lines.push('');
  lines.push(`1. **Architecture & Feature Reconstruction**: *"Using this AegisRE report for \`${targetName}\`, map out its main subsystems, entry flow, third-party dependencies, and reconstruct a clean high-level specification or source skeleton."*`);
  lines.push(`2. **Security & Privacy Audit**: *"Review the security mitigations, imported APIs, URLs, Registry paths, and licensing/crypto clues in this \`${targetName}\` report. Identify attack surface, network telemetry, privilege requirements, and hardening gaps."*`);
  lines.push(`3. **Interop, Hooking & Plugin Integration**: *"Based on the exported symbols, IAT addresses, and calling conventions in this report for \`${targetName}\`, generate safe wrapper/interop bindings or diagnostic instrumentation."*`);
  lines.push(`4. **Deeper Address Investigation**: *"Identify the highest-value addresses or virtual functions referenced in Section 5 and Section 6 that I should disassemble next using AegisRE's Go To Address decoder or MCP tools (\`aegis_inspect_file\`)."*`);
  lines.push('');

  return lines.join('\n');
}

module.exports = {
  analyzeBinaryTarget,
  disassembleFunctionAtAddress,
  detectGhidraInstallation,
  generateAntigravityReport,
};
