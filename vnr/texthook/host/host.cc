// host.cc
// 8/24/2013 jichi
// Branch IHF/main.cpp, rev 111
// 8/24/2013 TODO: Clean up this file

//#ifdef _MSC_VER
//# pragma warning(disable:4800) // C4800: forcing value to bool (performance warning)
//#endif // _MSC_VER

//#include "customfilter.h"
#include "growl.h"
#include "host.h"
#include "host_p.h"
#include "settings.h"
#include "vnrhook/include/const.h"
#include "vnrhook/include/defs.h"
#include "vnrhook/include/types.h"
#include "ithsys/ithsys.h"
#include "windbg/inject.h"
#include "ccutil/ccmacro.h"
#include <commctrl.h>

//#define ITH_WINE
//#define ITH_USE_UX_DLLS  IthIsWine()
//#define ITH_USE_XP_DLLS  (IthIsWindowsXp() && !IthIsWine())

#define DEBUG "vnrhost/host.cc"
#include "sakurakit/skdebug.h"

namespace { // unnamed

//enum { HOOK_TIMEOUT = -50000000 }; // in nanoseconds = 5 seconds

CRITICAL_SECTION cs;
//WCHAR exist[] = ITH_PIPEEXISTS_EVENT;
//WCHAR mutex[] = L"ITH_RUNNING";
//WCHAR EngineName[] = ITH_ENGINE_DLL;
//WCHAR EngineNameXp[] = ITH_ENGINE_XP_DLL;
//WCHAR DllName[] = ITH_CLIENT_DLL;
//WCHAR DllNameXp[] = ITH_CLIENT_XP_DLL;
HANDLE hServerMutex; // jichi 9/28/2013: used to guard pipe
HANDLE hHookMutex;  // jichi 9/28/2013: used to guard hook modification
} // unnamed namespace

//extern LPWSTR current_dir;
extern CRITICAL_SECTION detach_cs;

Settings *settings;
HWND hMainWnd;
HANDLE hPipeExist;
BOOL running;

#define ITH_SYNC_HOOK   IthMutexLocker locker(::hHookMutex)

namespace { // unnamed

void GetDebugPriv()
{
  HANDLE  hToken;
  DWORD  dwRet;

  TOKEN_PRIVILEGES Privileges = {1,{0x14,0,SE_PRIVILEGE_ENABLED}};

  OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
  AdjustTokenPrivileges(hToken, 0, &Privileges, sizeof(Privileges), 0, &dwRet);
  CloseHandle(hToken);
}

bool Inject(HANDLE hProc)
{
  wchar_t path[MAX_PATH];
  size_t len = IthGetCurrentModulePath(path, MAX_PATH);
  if (!len)
    return false;

  wchar_t *p;
  for (p = path + len; *p != L'\\'; p--);
  p++; // ending with L"\\"
  ::wcscpy(p, ITH_DLL);

  return injectDllW(path, hProc);
}

} // unnamed namespace

void CreateNewPipe();

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
  CC_UNUSED(lpvReserved);
  switch (fdwReason)
  {
  case DLL_PROCESS_ATTACH:
    DisableThreadLibraryCalls(hinstDLL);
    InitializeCriticalSection(&::cs);
    IthInitSystemService();
    GetDebugPriv();
    InitCommonControls();
    // jichi 8/24/2013: Create hidden window so that ITH can access timer and events
    hMainWnd = CreateWindowW(L"Button", L"InternalWindow", 0, 0, 0, 0, 0, 0, 0, hinstDLL, 0);
    break;
  case DLL_PROCESS_DETACH:
    if (::running)
      Host_Close();
    DeleteCriticalSection(&::cs);
    IthCloseSystemService();
    //wm_destroy_window(hMainWnd);
	DestroyWindow(hMainWnd);
    break;
  default:
    break;
  }
  return true;
}

enum { IHS_SIZE = 0x80 };
enum { IHS_BUFF_SIZE  = IHS_SIZE - sizeof(HookParam) };

struct InsertHookStruct
{
  SendParam sp;
  BYTE name_buffer[IHS_SIZE];
};

IHFSERVICE BOOL IHFAPI Host_Open()
{
  BOOL result = false;
  EnterCriticalSection(&::cs);
  
  if ((hServerMutex = CreateMutexW(nullptr, TRUE, ITH_SERVER_MUTEX)) == NULL || GetLastError() == ERROR_ALREADY_EXISTS)
    //MessageBox(0,L"Already running.",0,0);
    // jichi 8/24/2013
    GROWL_WARN(L"I am sorry that this game is attached by some other VNR ><\nPlease restart the game and try again!");
  else if (!::running) {
    ::running = true;
    ::settings = new Settings;
    ::man = new HookManager;
    //cmdq = new CommandQueue;
    InitializeCriticalSection(&detach_cs);

    ::hHookMutex = CreateMutexW(nullptr, FALSE, ITH_SERVER_HOOK_MUTEX);
    result = true;
  }
  LeaveCriticalSection(&::cs);
  return result;
}

IHFSERVICE DWORD IHFAPI Host_Start()
{
  //IthBreak();
  CreateNewPipe();
  ::hPipeExist = IthCreateEvent(ITH_PIPEEXISTS_EVENT);
  NtSetEvent(::hPipeExist, nullptr);
  /*char buff[1];
  man->AddConsoleOutput(buff);*/
  return 0;
}

IHFSERVICE DWORD IHFAPI Host_Close()
{
  BOOL result = FALSE;
  EnterCriticalSection(&::cs);
  if (::running) {
    ::running = FALSE;
    HANDLE hRecvPipe = IthOpenPipe(recv_pipe, GENERIC_WRITE);
    CloseHandle(hRecvPipe);
    ResetEvent(::hPipeExist);
    //delete cmdq;
    delete man;
    delete settings;
    CloseHandle(::hHookMutex);
    CloseHandle(hServerMutex);
    CloseHandle(::hPipeExist);
    DeleteCriticalSection(&detach_cs);
    result = TRUE;
  }
  LeaveCriticalSection(&::cs);
  return result;
}

IHFSERVICE bool IHFAPI Host_InjectByPID(DWORD pid)
{
  WCHAR str[0x80];
  if (!::running)
    return 0;
  if (pid == current_process_id) {
    //ConsoleOutput(SelfAttach);
    DOUT("refuse to inject myself");
    return false;
  }
  if (man->GetProcessRecord(pid)) {
    //ConsoleOutput(AlreadyAttach);
    man->AddConsoleOutput(L"already attached");
    return false;
  }
  swprintf(str, ITH_HOOKMAN_MUTEX_ L"%d", pid);
  HANDLE temp = CreateMutexW(nullptr, FALSE, str);
  if (temp == NULL) {
    man->AddConsoleOutput(L"already locked");
	CloseHandle(temp);
    return false;
  }
  CloseHandle(temp);
  return Inject(OpenProcess(
	  PROCESS_QUERY_INFORMATION|
	  PROCESS_CREATE_THREAD|
	  PROCESS_VM_OPERATION|
	  PROCESS_VM_READ|
	  PROCESS_VM_WRITE,
	  FALSE, pid)
  );
}

// jichi 7/16/2014: Test if process is valid before creating remote threads
// See: http://msdn.microsoft.com/en-us/library/ms687032.aspx
static bool isProcessTerminated(HANDLE hProc)
{ return WAIT_OBJECT_0 == ::WaitForSingleObject(hProc, 0); }

IHFSERVICE bool IHFAPI Host_ActiveDetachProcess(DWORD pid)
{
  ITH_SYNC_HOOK;

  //man->LockHookman();
  ProcessRecord *pr = man->GetProcessRecord(pid);
  HANDLE hCmd = man->GetCmdHandleByPID(pid);
  if (pr == 0 || hCmd == 0)
    return false;
  HANDLE hProc;
  //hProc = pr->process_handle; //This handle may be closed(thus invalid) during the detach process.
  NtDuplicateObject(NtCurrentProcess(), pr->process_handle,
      NtCurrentProcess(), &hProc, 0, 0, DUPLICATE_SAME_ACCESS); // Make a copy of the process handle.

  // jichi 7/15/2014: Process already closed
  if (isProcessTerminated(hProc)) {
    DOUT("process has terminated");
    return false;
  }

  man->AddConsoleOutput(L"send detach command");
  DWORD ret,
	  command = (DWORD)(HOST_COMMAND_DETACH);
  WriteFile(hCmd, &command, sizeof(DWORD), &ret, NULL);
  CloseHandle(hProc);

  return ret == 4;
}

IHFSERVICE DWORD IHFAPI Host_GetHookManager(HookManager** hookman)
{
  if (::running) {
    *hookman = man;
    return 0;
  }
  else
    return 1;
}

IHFSERVICE bool IHFAPI Host_GetSettings(Settings **p)
{
  if (::running) {
    *p = settings;
    return true;
  }
  else
    return false;
}

IHFSERVICE DWORD IHFAPI Host_InsertHook(DWORD pid, HookParam *hp, LPCSTR name)
{
  ITH_SYNC_HOOK;

  HANDLE hCmd = man->GetCmdHandleByPID(pid);
  if (hCmd == 0)
    return -1;

  InsertHookStruct s;
  s.sp.type = HOST_COMMAND_NEW_HOOK;
  s.sp.hp = *hp;
  size_t len;
  if (name)
    len = ::strlen(name);
  else
    len = 0;
  if (len) {
    if (len >= IHS_BUFF_SIZE) len = IHS_BUFF_SIZE - 1;
    memcpy(s.name_buffer, name, len);
  }
  s.name_buffer[len] = 0;
  IO_STATUS_BLOCK ios;
  NtWriteFile(hCmd, 0,0,0, &ios, &s, IHS_SIZE, 0, 0);

  //memcpy(&sp.hp,hp,sizeof(HookParam));
  //cmdq->AddRequest(sp, pid);
  return 0;
}

IHFSERVICE DWORD IHFAPI Host_RemoveHook(DWORD pid, DWORD addr)
{
  ITH_SYNC_HOOK;

  HANDLE hRemoved,hCmd;
  hCmd = GetCmdHandleByPID(pid);
  if (hCmd == 0)
    return -1;
  hRemoved = IthCreateEvent(ITH_REMOVEHOOK_EVENT);
  SendParam sp = {};
  IO_STATUS_BLOCK ios;
  sp.type = HOST_COMMAND_REMOVE_HOOK;
  sp.hp.address = addr;
  //cmdq -> AddRequest(sp, pid);
  NtWriteFile(hCmd, 0,0,0, &ios, &sp, sizeof(SendParam),0,0);
  // jichi 10/22/2013: Timeout might crash vnrsrv
  //const LONGLONG timeout = HOOK_TIMEOUT;
  //NtWaitForSingleObject(hRemoved, 0, (PLARGE_INTEGER)&timeout);
  NtWaitForSingleObject(hRemoved, 0, nullptr);
  CloseHandle(hRemoved);
  man -> RemoveSingleHook(pid, sp.hp.address);
  return 0;
}

// EOF
