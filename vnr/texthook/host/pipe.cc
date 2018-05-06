// vnrhost/pipe.cc
// 8/24/2013 jichi
// Branch IHF/pipe.cpp, rev 93
// 8/24/2013 TODO: Clean up this file

#include "host_p.h"
#include "hookman.h"
#include "vnrhook/include/defs.h"
#include "vnrhook/include/const.h"
#include "ithsys/ithsys.h"
#include <stdio.h>
#include "growl.h"
//#include "CommandQueue.h"
//#include <QtCore/QDebug>

#define DEBUG "vnrhost/pipe.cc"
#include "sakurakit/skdebug.h"

//DWORD WINAPI UpdateWindows(LPVOID lpThreadParameter);

namespace { // unnamed
	enum NamedPipeCommand {
		NAMED_PIPE_DISCONNECT = 1
		, NAMED_PIPE_CONNECT = 2
	};
}

wchar_t recv_pipe[] = ITH_TEXT_PIPE;
wchar_t command_pipe[] = ITH_COMMAND_PIPE;

CRITICAL_SECTION detach_cs; // jichi 9/27/2013: also used in main
//HANDLE hDetachEvent;
extern HANDLE hPipeExist;

void DetachFromProcess(DWORD pid);

void CreateNewPipe()
{
  HANDLE hTextPipe, hCmdPipe, hThread;

  hTextPipe = CreateNamedPipeW(ITH_TEXT_PIPE, PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, 0x1000, 0x1000, MAXDWORD, NULL);
  hCmdPipe = CreateNamedPipeW(ITH_COMMAND_PIPE, PIPE_ACCESS_OUTBOUND, 0, PIPE_UNLIMITED_INSTANCES, 0x1000, 0x1000, MAXDWORD, NULL);
  hThread = IthCreateRemoteThread(RecvThread, (DWORD)hTextPipe);
  man->RegisterPipe(hTextPipe, hCmdPipe, hThread);
}


DWORD WINAPI RecvThread(LPVOID lpThreadParameter)
{
	HANDLE hTextPipe = (HANDLE)lpThreadParameter;

	//Sleep(1000);

	int len;
	IO_STATUS_BLOCK ios = {};
	if (!::running) {
		CloseHandle(hTextPipe);
		return 0;
	}

	BYTE *buff;

	enum { PipeBufferSize = 0x1000 };
	buff = new BYTE[PipeBufferSize];
	::memset(buff, 0, PipeBufferSize); // jichi 8/27/2013: zero memory, or it will crash wine on start up
									   //WaitForSingleObject(hTextPipe, 3000);
	NtReadFile(hTextPipe, 0, 0, 0, &ios, buff, sizeof(DWORD), 0, 0);

	// jichi 7/2/2015: This must be consistent with the struct declared in vnrhook/pipe.cc
	DWORD pid = *(DWORD *)buff;
	man->RegisterProcess(pid);

	// jichi 9/27/2013: why recursion?
	// Artikash 4/28/2018 to create another pipe for another process to attach to
	CreateNewPipe();

	//CloseHandle(IthCreateThread(UpdateWindows,0));
	while (::running) {
		if (!NT_SUCCESS(NtReadFile(hTextPipe,
			0, 0, 0,
			&ios,
			buff,
			0xf80,
			0, 0)))
			break;

		man->AddConsoleOutput(L"File read success");

		enum { data_offset = 0xc }; // jichi 10/27/2013: Seem to be the data offset in the pipe

		DWORD RecvLen = ios.uInformation;
		if (RecvLen < data_offset)
		{
			wchar_t buffer[30];
			swprintf(buffer, L"%d", RecvLen);
			man->AddConsoleOutput(buffer);
			break;
		}
			
		DWORD hook = *(DWORD *)buff;

		union { DWORD retn; DWORD cmd_type; };
		union { DWORD split; DWORD new_engine_type; };

		retn = *(DWORD *)(buff + 4);
		split = *(DWORD *)(buff + 8);

		buff[RecvLen] = 0;
		buff[RecvLen + 1] = 0;

		if (hook == HOST_NOTIFICATION) {
			switch (cmd_type) {
			case HOST_NOTIFICATION_NEWHOOK:
			{
				static long lock;
				while (InterlockedExchange(&lock, 1) == 1);
				ProcessEventCallback new_hook = man->ProcessNewHook();
				if (new_hook)
					new_hook(pid);
				lock = 0;
			} break;
			case HOST_NOTIFICATION_TEXT:
				USES_CONVERSION;
				man->AddConsoleOutput(A2W((LPCSTR)(buff + 8)));
				break;
			}
		}
		else {
			// jichi 9/28/2013: Debug raw data
			//ITH_DEBUG_DWORD9(RecvLen - 0xc,
			//    buff[0xc], buff[0xd], buff[0xe], buff[0xf],
			//    buff[0x10], buff[0x11], buff[0x12], buff[0x13]);

			const BYTE *data = buff + data_offset; // th
			len = RecvLen - data_offset;
			man->DispatchText(pid, data, hook, retn, split, len, false);
		}
	}

	EnterCriticalSection(&detach_cs);

	HANDLE hDisconnect = IthCreateEvent(nullptr);

	if (STATUS_PENDING == NtFsControlFile(
		hTextPipe,
		hDisconnect,
		0, 0,
		&ios,
		CTL_CODE(FILE_DEVICE_NAMED_PIPE, NAMED_PIPE_DISCONNECT, 0, 0),
		0, 0, 0, 0)
	)
		NtWaitForSingleObject(hDisconnect, 0, 0);

	CloseHandle(hDisconnect);
	DetachFromProcess(pid);
	man->UnRegisterProcess(pid);

	//NtClearEvent(hDetachEvent);

	LeaveCriticalSection(&detach_cs);
	delete[] buff;

	/*if (::running)
	man->AddConsoleOutput(L"detached");*/

	return 0;
}

void DetachFromProcess(DWORD pid)
{
  HANDLE hMutex = INVALID_HANDLE_VALUE;
  IO_STATUS_BLOCK ios;
  ProcessRecord *pr = man->GetProcessRecord(pid);
  if (!pr)
    return;

  WCHAR mutex[0x20];
  swprintf(mutex, ITH_DETACH_MUTEX_ L"%d", pid);
  hMutex = IthOpenMutex(mutex);
  if (hMutex != INVALID_HANDLE_VALUE) {
    WaitForSingleObject(hMutex, MAXDWORD);
    ReleaseMutex(hMutex);
    CloseHandle(hMutex);
  }
  if (::running)
    SetEvent(hPipeExist);
}

// EOF
