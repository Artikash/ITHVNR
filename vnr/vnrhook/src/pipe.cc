// vnrhook/pipe.cc
// 8/24/2013 jichi
// Branch: ITH_DLL/pipe.cpp, rev 66
// 8/24/2013 TODO: Clean up this file

#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
#endif // _MSC_VER

#include "src/hijack/texthook.h"
#include "src/engine/match.h"
#include "src/util/util.h"
#include "src/main.h"
#include "include/defs.h"
//#include "src/util/growl.h"
#include "ithsys/ithsys.h"
#include "ccutil/ccmacro.h"
#include <cstdio> // for swprintf

//#include <ITH\AVL.h>
//#include <ITH\ntdll.h>
WCHAR detach_mutex[0x20];
//WCHAR write_event[0x20];
//WCHAR engine_event[0x20];

//WCHAR recv_pipe[] = L"\\??\\pipe\\ITH_PIPE";
//WCHAR command[] = L"\\??\\pipe\\ITH_COMMAND";
wchar_t recv_pipe[] = ITH_TEXT_PIPE;
wchar_t command[] = ITH_COMMAND_PIPE;

LARGE_INTEGER wait_time = {-100*10000, -1};
LARGE_INTEGER sleep_time = {-20*10000, -1};

DWORD engine_type;
DWORD module_base;

HANDLE hPipe, //pipe
       hCommand, //pipe
       hDetach; //mutex

DWORD WINAPI WaitForPipe(LPVOID lpThreadParameter) // Dynamically detect ITH main module status.
{
  // jichi 7/2/2015:This must be consistent with the struct declared in vnrhost/pipe.cc
  struct {
    DWORD pid;
    DWORD module;
    TextHook *man;
    //DWORD engine;
  } u;

  swprintf(::detach_mutex, ITH_DETACH_MUTEX_ L"%d", current_process_id);

  u.module = module_base;
  u.pid = current_process_id;
  u.man = hookman;
  //u.engine = engine_base; // jichi 10/19/2014: disable the second dll
  HANDLE hPipeExist = IthOpenEvent(ITH_PIPEEXISTS_EVENT);
  IO_STATUS_BLOCK ios;
  //hLose=IthCreateEvent(lose_event,0,0);
  if (hPipeExist != INVALID_HANDLE_VALUE)
  while (::running) {
    ::hPipe = INVALID_HANDLE_VALUE;
    hCommand = INVALID_HANDLE_VALUE;
    while (NtWaitForSingleObject(hPipeExist, 0, &wait_time) == WAIT_TIMEOUT)
      if (!::running)
        goto _release;
    HANDLE hMutex = IthCreateMutex(ITH_GRANTPIPE_MUTEX, 0);
    NtWaitForSingleObject(hMutex, 0, 0);
    while (::hPipe == INVALID_HANDLE_VALUE||
      hCommand == INVALID_HANDLE_VALUE) {
      NtDelayExecution(0, &sleep_time);
      if (::hPipe == INVALID_HANDLE_VALUE)
        ::hPipe = IthOpenPipe(recv_pipe, GENERIC_WRITE);
      if (hCommand == INVALID_HANDLE_VALUE)
        hCommand = IthOpenPipe(command, GENERIC_READ);
    }
    //NtClearEvent(hLose);
    NtWriteFile(::hPipe, 0, 0, 0, &ios, &u, sizeof(u), 0, 0);
    for (int i = 0, count = 0; count < ::current_hook; i++)
      if (hookman[i].RecoverHook()) // jichi 9/27/2013: This is the place where built-in hooks like TextOutA are inserted
        count++;
    //ConsoleOutput(dll_name);
    //OutputDWORD(tree->Count());
    NtReleaseMutant(hMutex,0);
    NtClose(hMutex);


    ::live = true;

    // jichi 7/17/2014: Always hijack by default or I have to wait for it is ready
    Engine::hijack();
	ConsoleOutput("vnrcli:WaitForPipe: pipe connected");

    ::hDetach = IthCreateMutex(::detach_mutex,1);
    while (::running && NtWaitForSingleObject(hPipeExist, 0, &sleep_time) == WAIT_OBJECT_0)
      NtDelayExecution(0, &sleep_time);
    ::live = false;

    for (int i = 0, count = 0; count < ::current_hook; i++)
      if (hookman[i].RemoveHook())
        count++;
    if (!::running) {
      //CliLockPipe();
      //NtWriteFile(::hPipe, 0, 0, 0, &ios, man, 4, 0, 0);
      NtWriteFile(::hPipe, 0, 0, 0, &ios, hookman, 4, 0, 0);
      //CliUnlockPipe();
      ReleaseMutex(::hDetach);
    }
    NtClose(::hDetach);
    NtClose(::hPipe);
  }
_release:
  //NtClose(hLose);
  NtClose(hPipeExist);
  return 0;
}

DWORD WINAPI CommandPipe(LPVOID lpThreadParameter)
{
  CC_UNUSED(lpThreadParameter);
  DWORD command;
  BYTE buff[0x400] = {};
  HANDLE hPipeExist;
  hPipeExist = IthOpenEvent(ITH_PIPEEXISTS_EVENT);
  IO_STATUS_BLOCK ios={};

  if (hPipeExist != INVALID_HANDLE_VALUE)
    while (::running) {
      while (!::live) {
        if (!::running)
          goto _detach;
        NtDelayExecution(0, &sleep_time);
      }
      // jichi 9/27/2013: Why 0x200 not 0x400? wchar_t?
      switch (NtReadFile(hCommand, 0, 0, 0, &ios, buff, 0x200, 0, 0)) {
      case STATUS_PIPE_BROKEN:
      case STATUS_PIPE_DISCONNECTED:
        NtClearEvent(hPipeExist);
        continue;
      case STATUS_PENDING:
        NtWaitForSingleObject(hCommand, 0, 0);
        switch (ios.Status) {
        case STATUS_PIPE_BROKEN:
        case STATUS_PIPE_DISCONNECTED:
          NtClearEvent(hPipeExist);
          continue;
        case 0: break;
        default:
          if (NtWaitForSingleObject(::hDetach, 0, &wait_time) == WAIT_OBJECT_0)
            goto _detach;
        }
      }
      if (ios.uInformation && ::live) {
        command = *(DWORD *)buff;
        switch(command) {
        case HOST_COMMAND_NEW_HOOK:
          //IthBreak();
          buff[ios.uInformation] = 0;
          //buff[ios.uInformation + 1] = 0;
          NewHook(*(HookParam *)(buff + 4), (LPSTR)(buff + 4 + sizeof(HookParam)), 0);
          break;
        case HOST_COMMAND_REMOVE_HOOK:
          {
            DWORD rm_addr = *(DWORD *)(buff+4);
            HANDLE hRemoved = IthOpenEvent(ITH_REMOVEHOOK_EVENT);

            TextHook *in = hookman;
            for (int i = 0; i < current_hook; in++) {
              if (in->Address()) i++;
              if (in->Address() == rm_addr) break;
            }
            if (in->Address())
              in->ClearHook();
            IthSetEvent(hRemoved);
            NtClose(hRemoved);
          } break;
        case HOST_COMMAND_DETACH:
          ::running = false;
          ::live = false;
          goto _detach;
        }
      }
    }
_detach:
  NtClose(hPipeExist);
  NtClose(hCommand);
  Util::unloadCurrentModule(); // jichi: this is not always needed
  return 0;
}
//extern "C" {
void ConsoleOutput(LPCSTR text)
{ // jichi 12/25/2013: Rewrite the implementation
  if (!live || !text)
    return;
  enum { buf_size = 0x50 };
  BYTE buf[buf_size]; // buffer is needed to append the message header
  size_t text_size = strlen(text) + 1;
  size_t data_size = text_size + 8;

  BYTE *data = (data_size <= buf_size) ? buf : new BYTE[data_size];
  *(DWORD *)data = HOST_NOTIFICATION; //cmd
  *(DWORD *)(data + 4) = HOST_NOTIFICATION_TEXT; //console
  memcpy(data + 8, text, text_size);

  IO_STATUS_BLOCK ios;
  NtWriteFile(hPipe, 0, 0, 0, &ios, data, data_size, 0, 0);
  if (data != buf)
    delete[] data;
}

DWORD NotifyHookInsert(DWORD addr)
{
  if (live) {
    BYTE buffer[0x10];
    *(DWORD *)buffer = HOST_NOTIFICATION;
    *(DWORD *)(buffer + 4) = HOST_NOTIFICATION_NEWHOOK;
    *(DWORD *)(buffer + 8) = addr;
    *(DWORD *)(buffer + 0xc) = 0;
    IO_STATUS_BLOCK ios;
    NtWriteFile(hPipe,0,0,0,&ios,buffer,0x10,0,0);
  }
  return 0;
}
//} // extern "C"

// EOF
