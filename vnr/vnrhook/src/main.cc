// main.cc
// 8/24/2013 jichi
// Branch: ITH_DLL/main.cpp, rev 128
// 8/24/2013 TODO: Clean up this file

#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
//# pragma warning (disable:4733)   // C4733: Inline asm assigning to 'FS:0' : handler not registered as safe handler
#endif // _MSC_VER

#include "src/main.h"
#include "src/tree/avl.h"
#include "src/engine/match.h"
#include "src/hijack/texthook.h"
#include "src/util/growl.h"
#include "src/except.h"
#include "include/const.h"
#include "include/defs.h"
#include "ithsys/ithsys.h"
#include "ccutil/ccmacro.h"
#include <cstdio> // for swprintf
//#include "ntinspect/ntinspect.h"
//#include "winseh/winseh.h"
//#include <boost/foreach.hpp>
//#include "md5.h"
//#include <ITH\AVL.h>
//#include <ITH\ntdll.h>

// Global variables

// jichi 6/3/2014: memory range of the current module
DWORD processStartAddress,
      processStopAddress;

enum { HOOK_BUFFER_SIZE = MAX_HOOK * sizeof(TextHook) };
//#define MAX_HOOK (HOOK_BUFFER_SIZE/sizeof(TextHook))
DWORD hook_buff_len = HOOK_BUFFER_SIZE;

namespace { FilterRange _filter[IHF_FILTER_CAPACITY]; }
FilterRange *filter = _filter;

WCHAR hm_section[0x100];
HINSTANCE hDLL;
HANDLE hSection;
bool running,
     live = false;
int current_hook = 0,
    user_hook_count = 0;
DWORD trigger = 0;
HANDLE
    hFile,
    hMutex,
    hmMutex;
//DWORD current_process_id;
extern DWORD enter_count;
//extern LPWSTR current_dir;
extern DWORD engine_type;
extern DWORD module_base;

namespace { // unnamed

	LPCWSTR GetProcessName()
	{
		wchar_t fullProcessName[MAX_PATH];
		wchar_t* processName = fullProcessName + GetModuleFileNameW(nullptr, fullProcessName, MAX_PATH);
		while (*(--processName) != L'\\');
		return processName + 1;
	}

void RequestRefreshProfile()
{
  if (::live) {
    BYTE buffer[0x80] = {}; // 11/14/2013: reset to zero. Shouldn't it be 0x8 instead of 0x80?
    *(DWORD *)buffer = HOST_NOTIFICATION;
    *(DWORD *)(buffer + 4) = HOST_NOTIFICATION_NEWHOOK;
    *(DWORD *)(buffer + 8) = 0;
    IO_STATUS_BLOCK ios;
    NtWriteFile(hPipe, 0, 0, 0, &ios, buffer, HEADER_SIZE, 0, 0);
  }
}

} // unnamed namespace

DWORD GetFunctionAddr(const char *name, DWORD *addr, DWORD *base, DWORD *size, LPWSTR *base_name)
{
    return FALSE;
}

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD fdwReason, LPVOID lpReserved)
{
  static HANDLE hSendThread,
                hCmdThread;

  CC_UNUSED(lpReserved);

  //static WCHAR dll_exist[] = L"ITH_DLL_RUNNING";
  //static WCHAR dll_exist[] = ITH_CLIENT_MUTEX;
  //static HANDLE hDllExist;

  // jichi 9/23/2013: wine deficenciy on mapping sections
  // Whe set to false, do not map sections.
  //static bool ith_has_section = true;
  switch (fdwReason) {
  case DLL_PROCESS_ATTACH:
    {
	  
      static bool attached_ = false;
      if (attached_) // already attached
        return TRUE;
      attached_ = true;

      DisableThreadLibraryCalls(hModule);

      //IthBreak();
      ::module_base = (DWORD)hModule;

      //if (!IthInitSystemService()) {
      //  GROWL_WARN(L"Initialization failed.\nAre you running game on a network drive?");
      //  return FALSE;
      //}
      // No longer checking if SystemService fails, which could happen on non-Japanese OS
      IthInitSystemService();

      swprintf(hm_section, ITH_SECTION_ L"%d", current_process_id);

      // jichi 9/25/2013: Interprocedural communication with vnrsrv.
      hSection = IthCreateSection(hm_section, HOOK_SECTION_SIZE, PAGE_EXECUTE_READWRITE);
      ::hookman = nullptr;
      NtMapViewOfSection(hSection, NtCurrentProcess(),
          (LPVOID *)&::hookman, 0, hook_buff_len, 0, &hook_buff_len, ViewUnmap, 0,
          PAGE_EXECUTE_READWRITE);

      FillRange(::GetProcessName(), &::processStartAddress, &::processStopAddress);
      //NtInspect::getProcessMemoryRange(&::processStartAddress, &::processStopAddress);

      //if (!::hookman) {
      //  ith_has_section = false;
      //  ::hookman = new TextHook[MAX_HOOK];
      //  memset(::hookman, 0, MAX_HOOK * sizeof(TextHook));
      //}

      {
        wchar_t hm_mutex[0x100];
        swprintf(hm_mutex, ITH_HOOKMAN_MUTEX_ L"%d", current_process_id);
        ::hmMutex = CreateMutexW(nullptr, FALSE, hm_mutex);
      }
      {
        wchar_t dll_mutex[0x100];
        swprintf(dll_mutex, ITH_PROCESS_MUTEX_ L"%d", current_process_id);
        if ((::hMutex = CreateMutexW(nullptr, TRUE, dll_mutex)) == NULL || GetLastError() == ERROR_ALREADY_EXISTS)
          return FALSE;
      }

      //hDllExist = CreateMutexW(nullptr, FALSE, dll_exist);
      hDLL = hModule;
      ::running = true;
      ::current_available = ::hookman;
      InitFilterTable();

      hSendThread = IthCreateRemoteThread(WaitForPipe, 0);
      hCmdThread = IthCreateRemoteThread(CommandPipe, 0);
    } break;
  case DLL_PROCESS_DETACH:
    {
      static bool detached_ = false;
      if (detached_) // already detached
        return TRUE;
      detached_ = true;

      // jichi 10/2/2103: Cannot use __try in functions that require object unwinding
      //ITH_TRY {
      ::running = false;
      ::live = false;

      const LONGLONG timeout = -50000000; // in nanoseconds = 5 seconds

      Engine::terminate();

      if (hSendThread) {
        NtWaitForSingleObject(hSendThread, 0, (PLARGE_INTEGER)&timeout);
        CloseHandle(hSendThread);
      }

      if (hCmdThread) {
        NtWaitForSingleObject(hCmdThread, 0, (PLARGE_INTEGER)&timeout);
        CloseHandle(hCmdThread);
      }

      for (TextHook *man = ::hookman; man->RemoveHook(); man++);
      //LARGE_INTEGER lint = {-10000, -1};
      while (::enter_count)
        Sleep(1); // jichi 9/28/2013: sleep for 1 ms
        //NtDelayExecution(0, &lint);
      for (TextHook *man = ::hookman; man < ::hookman + MAX_HOOK; man++)
        man->ClearHook();
      //if (ith_has_section)
      NtUnmapViewOfSection(NtCurrentProcess(), ::hookman);
      //else
      //  delete[] ::hookman;
      CloseHandle(hSection);
      CloseHandle(hMutex);

      IthCloseSystemService();
      CloseHandle(hmMutex);
      //CloseHandle(hDllExist);
      //} ITH_EXCEPT {}
    } break;
  }
  return TRUE;
}

//extern "C" {
DWORD NewHook(const HookParam &hp, LPCSTR name, DWORD flag)
{
  CHAR str[128];
  int current = ::current_available - ::hookman;
  if (current < MAX_HOOK) {
    //flag &= 0xffff;
    //if ((flag & HOOK_AUXILIARY) == 0)
    flag |= HOOK_ADDITIONAL;
	if (name == NULL || name[0] == '\0')
	{
		sprintf(str, "UserHook%d", user_hook_count++);
	}
	else
	{
		strcpy(str, name);
	}

    ConsoleOutput("vnrcli:NewHook: try inserting hook");

    // jichi 7/13/2014: This function would raise when too many hooks added
    ::hookman[current].InitHook(hp, str, flag & 0xffff);

    if (::hookman[current].InsertHook() == 0) {
      ConsoleOutput("vnrcli:NewHook: hook inserted");
      //ConsoleOutputW(name);
      //swprintf(str,L"Insert address 0x%.8X.", hookman[current].Address());
      RequestRefreshProfile();
    } else
      ConsoleOutput("vnrcli:NewHook:WARNING: failed to insert hook");
  }
  return 0;
}
DWORD RemoveHook(DWORD addr)
{
  for (int i = 0; i < MAX_HOOK; i++)
    if (::hookman[i].Address ()== addr) {
      ::hookman[i].ClearHook();
      return 0;
    }
  return 0;
}

DWORD SwitchTrigger(DWORD t)
{
  trigger = t;
  return 0;
}

//} // extern "C"


namespace { // unnamed

BOOL SafeFillRange(LPCWSTR dll, DWORD *lower, DWORD *upper)
{
  BOOL ret = FALSE;
  ITH_WITH_SEH(ret = FillRange(dll, lower, upper));
  return ret;
}

} // unnamed namespace

// jichi 12/13/2013
// Use listdlls from SystemInternals
void InitFilterTable()
{
  LPCWSTR l[] = { IHF_FILTER_DLL_LIST };
  enum { capacity = sizeof(l)/sizeof(*l) };

  size_t count = 0;
  //for (auto p : l)
  for (size_t i = 0; i < capacity; i++)
    if (SafeFillRange(l[i], &::filter[count].lower, &::filter[count].upper))
      count++;
}

// EOF