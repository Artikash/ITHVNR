// inject.cc
// 1/27/2013 jichi
#include "windbg/inject.h"
#include "windbg/windbg_p.h"
#include <cwchar> // for wcslen

//#define DEBUG "windbg::inject"
#include "sakurakit/skdebug.h"

WINDBG_BEGIN_NAMESPACE

// - Remote Injection -

BOOL InjectFunction1(LPCVOID addr, LPCVOID data, SIZE_T dataSize, DWORD pid, HANDLE hProcess, INT timeout)
{
  DOUT("enter: pid =" <<  pid);
  if (hProcess == INVALID_HANDLE_VALUE && pid) {
     hProcess = ::OpenProcess(PROCESS_INJECT_ACCESS, FALSE, pid);
  }
  if (hProcess == INVALID_HANDLE_VALUE) {
    DOUT("exit: error: failed to get process handle");
    return FALSE;
  }

  BOOL ret = FALSE;
  if (LPVOID remoteData = ::VirtualAllocEx(hProcess, nullptr, dataSize, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE)) {
    if (::WriteProcessMemory(hProcess, remoteData, data, dataSize, nullptr))
      if (HANDLE hThread = ::CreateRemoteThread(
          hProcess,
          nullptr, 0,
          reinterpret_cast<LPTHREAD_START_ROUTINE>(addr),
          remoteData,
          0, nullptr)) {
        ::WaitForSingleObject(hThread, timeout);
        ::CloseHandle(hThread);
        ret = TRUE;
      }
    ::VirtualFreeEx(hProcess, remoteData, dataSize, MEM_RELEASE);
  }
  ::CloseHandle(hProcess);
  DOUT("exit: ret =" << ret);
  return ret;
}

BOOL injectDllW(LPCWSTR dllPath, DWORD pid, HANDLE hProcess, INT timeout)
{
  DOUT("enter: pid =" <<  pid);
  LPCVOID fun = details::getModuleFunctionAddressA("LoadLibraryW", "kernel32.dll");
  if (!fun) {
    DOUT("exit error: cannot find function");
    return FALSE;
  }
  LPCVOID data = dllPath;
  SIZE_T dataSize = ::wcslen(dllPath) * 2 + 2; // L'\0'
  return InjectFunction1(fun, data, dataSize, pid, hProcess, timeout);
}

BOOL ejectDll(HANDLE hDll, DWORD pid, HANDLE hProcess, INT timeout)
{
  DOUT("enter: pid =" <<  pid);
  LPCVOID fun = details::getModuleFunctionAddressA("FreeLibrary", "kernel32.dll");
  if (!fun) {
    DOUT("exit error: cannot find function");
    return FALSE;
  }
  LPCVOID data = &hDll;
  SIZE_T dataSize = sizeof(hDll);
  BOOL ok = InjectFunction1(fun, data, dataSize, pid, hProcess, timeout);
  DOUT("exit: ret =" << ok);
  return ok;
}

WINDBG_END_NAMESPACE

// EOF
