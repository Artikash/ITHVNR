// inject.cc
// 1/27/2013 jichi
#include "windbg/inject.h"
#include <cwchar> // for wcslen

//#define DEBUG "windbg::inject"
#include "sakurakit/skdebug.h"

// - Remote Injection -

BOOL InjectFunction1(LPCVOID addr, LPCVOID data, SIZE_T dataSize, HANDLE hProcess, INT timeout)
{
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

BOOL injectDllW(LPCWSTR dllPath, HANDLE hProcess, INT timeout)
{
  DOUT("enter: pid =" <<  pid);
  LPCVOID fun = ::GetProcAddress(::GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
  if (!fun) {
    DOUT("exit error: cannot find function");
    return FALSE;
  }
  LPCVOID data = dllPath;
  SIZE_T dataSize = ::wcslen(dllPath) * 2 + 2; // L'\0'
  return InjectFunction1(fun, data, dataSize, hProcess, timeout);
}

// EOF
