﻿// ithsys.cc
// 8/21/2013 jichi
// Branch: ITH_SYS/SYS.cpp, rev 126
//
// 8/24/2013 TODO:
// - Clean up the code
// - Move my old create remote thread for ITH2 here

#include "ithsys/ithsys.h"
//#include "vnrhook/src/util/growl.h"

// jichi 10/6/2013
// See: http://stackoverflow.com/questions/557081/how-do-i-get-the-hmodule-for-the-currently-executing-code
// See: http://www.codeproject.com/Articles/16598/Get-Your-DLL-s-Path-Name
EXTERN_C IMAGE_DOS_HEADER __ImageBase;
size_t IthGetCurrentModulePath(wchar_t *buf, size_t len)
{ return ::GetModuleFileName((HINSTANCE)&__ImageBase, buf, len); }

// - Global variables -

#ifdef ITH_HAS_HEAP
HANDLE hHeap; // used in ith/common/memory.h
#endif // ITH_HAS_HEAP

DWORD current_process_id;
BYTE launch_time[0x10];
LPVOID page;

// jichi 6/12/2015: https://en.wikipedia.org/wiki/Shift_JIS
// Leading table for SHIFT-JIS encoding
BYTE LeadByteTable[0x100] = {
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
  2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
  2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
  2,2,2,2,2,2,2,2,2,2,2,2,2,1,1,1
};

namespace { // unnamed
DWORD page_locale;
HANDLE root_obj,
       dir_obj,
       codepage_section,
       thread_man_section;

BYTE file_info[0x1000];


// - Helper functions -

inline DWORD GetShareMemory()
{
  __asm
  {
    mov eax,fs:[0x30]
    mov eax,[eax+0x4C]
  }
}

inline LARGE_INTEGER *GetTimeBias()
{ __asm mov eax,0x7ffe0020 }

// - Singleton classes -

BYTE normal_routine[0x14] = {
  0x51,0x52,0x64,0x89,0x23,0x55,0xff,0xd0,0x50,0x6a,0xfe,0xff,0x15,0x14,0x00,0x00,0x00
};

BYTE except_routine[0xe0] = {
  0xba,0x08,0x00,0x00,0x00,0x8b,0xc1,0x83,0xe0,0x0f,0x83,0xf8,0x0a,0x72,0x02,0x04,
  0x07,0x04,0x30,0x66,0xab,0xc1,0xc9,0x04,0x4a,0x75,0xea,0xc3,0x00,0x00,0x00,0x00,
  0x8b,0x44,0xe4,0x04,0x31,0xf6,0x8b,0x28,0x8b,0x4c,0xe4,0x0c,0x8b,0x99,0xb8,0x00,
  0x00,0x00,0x81,0xec,0x40,0x02,0x00,0x00,0x8d,0x7c,0xe4,0x40,0x89,0xe0,0x56,0x6a,
  0x1c,0x50,0x56,0x53,0x6a,0xff,0xff,0x15,0x18,0x00,0x00,0x00,0x85,0xc0,0x75,0x98,
  0x89,0xe0,0x50,0x68,0x00,0x02,0x00,0x00,0x57,0x6a,0x02,0x53,0x6a,0xff,0xff,0x15,
  0x18,0x00,0x00,0x00,0x85,0xc0,0x75,0xe6,0x5e,0x0f,0xc1,0xf7,0xfd,0xb0,0x5c,0x66,
  0xf2,0xaf,0x66,0xc7,0x47,0x02,0x3a,0x00,0x89,0xd9,0x2b,0x0c,0xe4,0xe8,0x7e,0xff,
  0xff,0xff,0x47,0x47,0x87,0xfe,0x89,0xe9,0xe8,0x73,0xff,0xff,0xff,0x47,0x47,0x31,
  0xc0,0x89,0x47,0x10,0x6a,0x00,0x57,0x56,0x6a,0x00,0xfc,0xff,0x15,0x1c,0x00,0x00,
  0x00,0x83,0xc8,0xff,0xeb,0xbe
};

// jichi 8/24/2013: Could be initialized using NtMapViewOfSection/ZwMapViewOfSection
// This class cannot have constructor / destructor
struct _ThreadView {
  UINT_PTR mutex,
           count;
  DWORD proc_record[1];
};

} // unnamed namespace

  // - API functions -

extern "C" {

int FillRange(LPCWSTR name, DWORD *lower, DWORD *upper)
{
  PLDR_DATA_TABLE_ENTRY it;
  LIST_ENTRY *begin;
  __asm
  {
    mov eax,fs:[0x30]
    mov eax,[eax+0xc]
    mov eax,[eax+0xc]
    mov it,eax
    mov begin,eax
  }

  while (it->SizeOfImage) {
    if (::_wcsicmp(it->BaseDllName.Buffer, name) == 0) {
      *lower = *upper = (DWORD)it->DllBase;
      MEMORY_BASIC_INFORMATION info = {};
      DWORD l,size;
      size = 0;
      do {
        NtQueryVirtualMemory(NtCurrentProcess(), (LPVOID)(*upper), MemoryBasicInformation, &info, sizeof(info), &l);
        if (info.Protect&PAGE_NOACCESS) {
          it->SizeOfImage=size;
          break;
        }
        size += info.RegionSize;
        *upper += info.RegionSize;
      } while (size < it->SizeOfImage);
      return 1;
    }
    it = (PLDR_DATA_TABLE_ENTRY)it->InLoadOrderModuleList.Flink;
    if (it->InLoadOrderModuleList.Flink == begin)
      break;
  }
  return 0;
}

DWORD SearchPattern(DWORD base, DWORD base_length, LPCVOID search, DWORD search_length) // KMP
{
  __asm
  {
    mov eax,search_length
alloc:
    push 0
    sub eax,1
    jnz alloc

    mov edi,search
    mov edx,search_length
    mov ecx,1
    xor esi,esi
build_table:
    mov al,byte ptr [edi+esi]
    cmp al,byte ptr [edi+ecx]
    sete al
    test esi,esi
    jz pre
    test al,al
    jnz pre
    mov esi,[esp+esi*4-4]
    jmp build_table
pre:
    test al,al
    jz write_table
    inc esi
write_table:
    mov [esp+ecx*4],esi

    inc ecx
    cmp ecx,edx
    jb build_table

    mov esi,base
    xor edx,edx
    mov ecx,edx
matcher:
    mov al,byte ptr [edi+ecx]
    cmp al,byte ptr [esi+edx]
    sete al
    test ecx,ecx
    jz match
    test al,al
    jnz match
    mov ecx, [esp+ecx*4-4]
    jmp matcher
match:
    test al,al
    jz pre2
    inc ecx
    cmp ecx,search_length
    je finish
pre2:
    inc edx
    cmp edx,base_length // search_length
    jb matcher
    mov edx,search_length
    dec edx
finish:
    mov ecx,search_length
    sub edx,ecx
    lea eax,[edx+1]
    lea ecx,[ecx*4]
    add esp,ecx
  }
}

// jichi 2/5/2014: '?' = 0xff
// See: http://sakuradite.com/topic/124
DWORD SearchPatternEx(DWORD base, DWORD base_length, LPCVOID search, DWORD search_length, BYTE wildcard) // KMP
{
  __asm
  {
    // jichi 2/5/2014 BEGIN
    mov bl,wildcard
    // jichi 2/5/2014 END
    mov eax,search_length
alloc:
    push 0
    sub eax,1
    jnz alloc // jichi 2/5/2014: this will also set %eax to zero

    mov edi,search
    mov edx,search_length
    mov ecx,1
    xor esi,esi
build_table:
    mov al,byte ptr [edi+esi]
    cmp al,byte ptr [edi+ecx]
    sete al
    test esi,esi
    jz pre
    test al,al
    jnz pre
    mov esi,[esp+esi*4-4]
    jmp build_table
pre:
    test al,al
    jz write_table
    inc esi
write_table:
    mov [esp+ecx*4],esi

    inc ecx
    cmp ecx,edx
    jb build_table

    mov esi,base
    xor edx,edx
    mov ecx,edx
matcher:
    mov al,byte ptr [edi+ecx] // search
    // jichi 2/5/2014 BEGIN
    mov bh,al // save loaded byte to reduce cache access. %ah is not used and always zero
    cmp al,bl // %bl is the wildcard byte
    sete al
    test al,al
    jnz wildcard_matched
    mov al,bh // restore the loaded byte
    // jichi 2/5/2014 END
    cmp al,byte ptr [esi+edx] // base
    sete al
    // jichi 2/5/2014 BEGIN
wildcard_matched:
    // jichi 2/5/2014 END
    test ecx,ecx
    jz match
    test al,al
    jnz match
    mov ecx, [esp+ecx*4-4]
    jmp matcher
match:
    test al,al
    jz pre2
    inc ecx
    cmp ecx,search_length
    je finish
pre2:
    inc edx
    cmp edx,base_length // search_length
    jb matcher
    mov edx,search_length
    dec edx
finish:
    mov ecx,search_length
    sub edx,ecx
    lea eax,[edx+1]
    lea ecx,[ecx*4]
    add esp,ecx
  }
}

DWORD IthGetMemoryRange(LPCVOID mem, DWORD *base, DWORD *size)
{
  DWORD r;
  MEMORY_BASIC_INFORMATION info;
  NtQueryVirtualMemory(NtCurrentProcess(), const_cast<LPVOID>(mem), MemoryBasicInformation, &info, sizeof(info), &r);
  if (base)
    *base = (DWORD)info.BaseAddress;
  if (size)
    *size = info.RegionSize;
  return (info.Type&PAGE_NOACCESS) == 0;
}

// jichi 9/25/2013
// See: http://publib.boulder.ibm.com/infocenter/pseries/v5r3/index.jsp?topic=/com.ibm.aix.nls/doc/nlsgdrf/multi-byte_widechar_subr.htm
// SJIS->Unicode. 'mb' must be null-terminated. 'wc' should have enough space ( 2*strlen(mb) is safe).
int MB_WC(char *mb, wchar_t *wc)
{
  __asm
  {
    mov esi,mb
    mov edi,wc
    mov edx,page
    lea ebx,LeadByteTable
    add edx,0x220
    push 0
_mb_translate:
    movzx eax,word ptr [esi]
    test al,al
    jz _mb_fin
    movzx ecx,al
    xlat
    test al,1
    cmovnz cx, word ptr [ecx*2+edx-0x204]
    jnz _mb_next
    mov cx,word ptr [ecx*2+edx]
    mov cl,ah
    mov cx, word ptr [ecx*2+edx]
_mb_next:
    mov [edi],cx
    add edi,2
    movzx eax,al
    add esi,eax
    inc dword ptr [esp]
    jmp _mb_translate
_mb_fin:
    pop eax
  }
}

// jichi 9/25/2013
// See: http://publib.boulder.ibm.com/infocenter/pseries/v5r3/index.jsp?topic=/com.ibm.aix.nls/doc/nlsgdrf/multi-byte_widechar_subr.htm
// Unicode->SJIS. Analogous to MB_WC.
int WC_MB(wchar_t *wc, char *mb)
{
  __asm
  {
    mov esi,wc
    mov edi,mb
    mov edx,page
    add edx,0x7c22
    xor ebx,ebx
_wc_translate:
    movzx eax,word ptr [esi]
    test eax,eax
    jz _wc_fin
    mov cx,word ptr [eax*2+edx]
    test ch,ch
    jz _wc_single
    mov [edi+ebx],ch
    inc ebx
_wc_single:
    mov [edi+ebx],cl
    inc ebx
    add esi,2
    jmp _wc_translate
_wc_fin:
    mov eax,ebx
  }
}

//Initialize environment for NT native calls. Not thread safe so only call it once in one module.
//1. Create new heap. Future memory requests are handled by this heap.
//Destroying this heap will completely release all dynamically allocated memory, thus prevent memory leaks on unload.
//2. Create handle to root directory of process objects (section/event/mutex/semaphore).
//NtCreate* calls will use this handle as base directory.
//3. Load SJIS code page. First check for Japanese locale. If not then load from 'C_932.nls' in system folder.
//MB_WC & WC_MB use this code page for translation.
//4. Locate current NT path (start with \??\).
//NtCreateFile requires full path or a root handle. But this handle is different from object.
//5. Map shared memory for ThreadStartManager into virtual address space.
//This will allow IthCreateThread function properly.
BOOL IthInitSystemService()
{
  PPEB peb;
  //NTSTATUS status;
  DWORD size;
  UNICODE_STRING us;
  OBJECT_ATTRIBUTES oa = {sizeof(oa), 0, &us, OBJ_CASE_INSENSITIVE, 0, 0};
  IO_STATUS_BLOCK ios;
  HANDLE codepage_file;
  LARGE_INTEGER sec_size = {0x1000, 0};
  __asm
  {
    mov eax,fs:[0x18]
    mov ecx,[eax+0x20]
    mov eax,[eax+0x30]
    mov peb,eax
    mov current_process_id,ecx
  }

#ifdef ITH_HAS_HEAP
  ::hHeap = RtlCreateHeap(0x1002, 0, 0, 0, 0, 0);
  RtlSetHeapInformation(::hHeap, HeapCompatibilityInformation, &LowFragmentHeap, sizeof(LowFragmentHeap));
#endif // ITH_HAS_HEAP

  LPWSTR t = nullptr,   // jichi: path to system32, such as "c:\windows\system32"
         obj = nullptr; // jichi: path to current kernel session, such as "Sessions\\1\\BaseNamedObjects"
		WCHAR file_path[MAX_PATH] = L"\\??\\";
    // jichi 9/22/2013: For ChuSingura46+1 on Windows 7
    //   t = L"C:\\Windows\\system32";
    //   obj = L"\\Sessions\\1\\BaseNamedObjects";
    // On Windows XP
    //   t = L"C:\\WINDOWS\\system32";
    //   obj = L"\\BaseNamedObjects";
    MEMORY_BASIC_INFORMATION info;
    if (!NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(), peb->ReadOnlySharedMemoryBase, MemoryBasicInformation, &info, sizeof(info), &size)))
      return FALSE;
    DWORD base = (DWORD)peb->ReadOnlySharedMemoryBase;
    DWORD end = base + info.RegionSize - 0x40;

	// I_Jemin 13/11/2016
	// Prevent redirecting SYSWOW64 to receive Shift-JIS
	PVOID OldValue;
	Wow64DisableWow64FsRedirection(&OldValue);

    static WCHAR system32[] = L"system32";
    for (;base < end; base += 2)
      if (::memcmp((PVOID)base, system32, 0x10) == 0) {
        t = (LPWSTR)base;
        while (*t-- != L':');
        obj = (LPWSTR)base;
        while (*obj != L'\\') obj++;
        break;
      }

	// Eguni 13/11/2016
	// Dispose redirection
	Wow64EnableWow64FsRedirection(FALSE);

    if (base == end)
      return FALSE;
  //ITH_MSG(t);
  //ITH_MSG(obj);

  LDR_DATA_TABLE_ENTRY *ldr_entry = (LDR_DATA_TABLE_ENTRY*)peb->Ldr->InLoadOrderModuleList.Flink;

  // jichi 7/12/2015: This will fail when the file path is a remote path such as:
  // Original remote file path: \\??\\\\\\psf\\Host\\Local\\Windows\\Games\\ShinaRio\\Ayakashibito_trial\\");
  // Correct UNC path: \\??\\\\UNC\\psf\\Host\\Local\\Windows\\Games\\ShinaRio\\Ayakashibito_trial\\");
  //RtlInitUnicodeString(&us, L"\\??\\UNC\\psf\\Host\\Local\\Windows\\Games\\ShinaRio\\Ayakashibito_trial\\");
  //WCHAR file_path[MAX_PATH] = L"\\??\\";
  LPCWSTR modulePath = ldr_entry->FullDllName.Buffer;
  if (modulePath[0] == '\\' && modulePath[1] == '\\') { // This is a remote path
    file_path[4] = 'U';
    file_path[5] = 'N';
    file_path[6] = 'C';
    ::wcscpy(file_path + 7, modulePath + 1);
  } else
    ::wcscpy(file_path + 4, modulePath);

  *(::wcsrchr(file_path, L'\\') + 1) = 0;

  //GROWL(::file_path);
  RtlInitUnicodeString(&us, file_path);

  if (!NT_SUCCESS(NtOpenFile(&dir_obj,FILE_LIST_DIRECTORY|FILE_TRAVERSE|SYNCHRONIZE,
      &oa,&ios,FILE_SHARE_READ|FILE_SHARE_WRITE,FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT)))
    return FALSE;

  // jichi 9/22/2013: Get kernel object session ID
  // See: http://www.brianbondy.com/blog/id/100/
  // It seems that on sessionId is 0 on Windows XP, and 1 on Windows Vista and later
  // I assume that sessionId is in [0,9]
  // For ChuSingura46+1 on Windows 7
  //    obj = L"\\Sessions\\1\\BaseNamedObjects";
  // On Windows XP
  //    obj = L"\\BaseNamedObjects";
  //ITH_MSG(obj);
  {
    if (obj)
      RtlInitUnicodeString(&us, obj);
    else { // jichi ITH is on Wine
      // Get session ID in PEB
      // See: http://msdn.microsoft.com/en-us/library/bb432286%28v=vs.85%29.aspx
      DWORD sessionId = peb->SessionId;
      if (!sessionId) // Windows XP
        RtlInitUnicodeString(&us, L"\\BaseNamedObjects");
      else { // Windows Vista +
        wchar_t path[] = L"\\Sessions\\0\\BaseNamedObjects";
        path[10] += (wchar_t)sessionId; // replace 0 with the session ID
        RtlInitUnicodeString(&us, path);
      }
    }
  }

  if (!NT_SUCCESS(NtOpenDirectoryObject(&::root_obj, READ_CONTROL|0xf, &oa)))
    return FALSE;

  ::page = peb->InitAnsiCodePageData;

  ::page_locale = *(DWORD *)page >> 16;

  if (::page_locale == 932) {
    //oa.hRootDirectory = ::root_obj;
    //oa.uAttributes |= OBJ_OPENIF;
  } else {
    ::wcscpy(file_path + 4, t);
    t = file_path;
    while(*++t);
    if (*(t-1)!=L'\\')
      *t++=L'\\';
    ::wcscpy(t,L"C_932.nls");
    RtlInitUnicodeString(&us, file_path);
    if (!NT_SUCCESS(NtOpenFile(&codepage_file, FILE_READ_DATA, &oa, &ios,FILE_SHARE_READ,0)))
      return FALSE;
    oa.hRootDirectory = ::root_obj;
    oa.uAttributes |= OBJ_OPENIF;
    RtlInitUnicodeString(&us, L"JPN_CodePage");
    if (!NT_SUCCESS(NtCreateSection(&codepage_section, SECTION_MAP_READ,
        &oa,0, PAGE_READONLY, SEC_COMMIT, codepage_file)))
      return FALSE;
    CloseHandle(codepage_file);
    size = 0;
    ::page = nullptr;
    if (!NT_SUCCESS(NtMapViewOfSection(::codepage_section, NtCurrentProcess(),
        &::page,
        0, 0, 0, &size, ViewUnmap, 0,
        PAGE_READONLY)))
      return FALSE;
  }
  return TRUE;
}

//Release resources allocated by IthInitSystemService.
//After destroying the heap, all memory allocated by ITH module is returned to system.
void IthCloseSystemService()
{
  if (::page_locale != 932) {
    NtUnmapViewOfSection(NtCurrentProcess(), ::page);
    CloseHandle(::codepage_section);
  }
  CloseHandle(::root_obj);
#ifdef ITH_HAS_HEAP
  RtlDestroyHeap(::hHeap);
#endif // ITH_HAS_HEAP
}

//Check for existence of a file in current folder. Thread safe after init.
//For ITH main module, it's ITH folder. For target process it's the target process's current folder.
BOOL IthCheckFile(LPCWSTR file)
{
    HANDLE hFile;
    IO_STATUS_BLOCK isb;
    UNICODE_STRING us;
    RtlInitUnicodeString(&us, file);
    OBJECT_ATTRIBUTES oa = { sizeof(oa), dir_obj, &us, 0, 0, 0};
    // jichi 9/22/2013: Following code does not work in Wine
    if (NT_SUCCESS(NtCreateFile(&hFile, FILE_READ_DATA, &oa, &isb, 0, 0, FILE_SHARE_READ, FILE_OPEN, 0, 0, 0))) {
      CloseHandle(hFile);
      return TRUE;
    }
  return FALSE;
  //return IthGetFileInfo(file,file_info);
  //wcscpy(current_dir,file);
}

//Check for existence of files in current folder.
//Unlike IthCheckFile, this function allows wildcard character.
BOOL IthFindFile(LPCWSTR file)
{
  NTSTATUS status;
  HANDLE h;
  UNICODE_STRING us;
  OBJECT_ATTRIBUTES oa = {sizeof(oa), dir_obj, &us, OBJ_CASE_INSENSITIVE, 0, 0};
  us.Buffer = const_cast<LPWSTR>(file);
  LPCWSTR path = wcsrchr(file, L'\\');
  if (path) {
    us.Length = (path - file) << 1;
    us.MaximumLength = us.Length;
  } else {
    us.Length = 0;
    us.MaximumLength = 0;
  }
  IO_STATUS_BLOCK ios;
  if (NT_SUCCESS(NtOpenFile(&h,FILE_LIST_DIRECTORY|SYNCHRONIZE,
      &oa,&ios,FILE_SHARE_READ,FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT))) {
    BYTE info[0x400];
    if (path)
      RtlInitUnicodeString(&us, path + 1);
    else
      RtlInitUnicodeString(&us, file);
    status = NtQueryDirectoryFile(h,0,0,0,&ios,info,0x400,FileBothDirectoryInformation,TRUE,&us,TRUE);
    CloseHandle(h);
    return NT_SUCCESS(status);
  }
  return FALSE;
}
//Analogous to IthFindFile, but return detail information in 'info'.
BOOL IthGetFileInfo(LPCWSTR file, LPVOID info, DWORD size)
{
  NTSTATUS status;
  HANDLE h;
  UNICODE_STRING us;
  LPCWSTR path = wcsrchr(file, L'\\');
  us.Buffer = const_cast<LPWSTR>(file);
  if (path) {
    us.Length = (path - file) << 1;
    us.MaximumLength = us.Length;
  } else {
    us.Length = 0;
    us.MaximumLength = 0;
  }
  //RtlInitUnicodeString(&us,file);
  OBJECT_ATTRIBUTES oa = {sizeof(oa), dir_obj, &us, OBJ_CASE_INSENSITIVE, 0, 0};
  IO_STATUS_BLOCK ios;
  if (NT_SUCCESS(NtOpenFile(&h,FILE_LIST_DIRECTORY|SYNCHRONIZE,
      &oa,&ios,FILE_SHARE_READ,FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT))) {
    RtlInitUnicodeString(&us,file);
    status = NtQueryDirectoryFile(h,0,0,0,&ios,info,size,FileBothDirectoryInformation,0,&us,0);
    status = NT_SUCCESS(status);
    CloseHandle(h);
  } else
    status = FALSE;
  return status;
}

//Check for existence of a file with full NT path(start with \??\).
BOOL IthCheckFileFullPath(LPCWSTR file)
{
  UNICODE_STRING us;
  RtlInitUnicodeString(&us, file);
  OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &us, OBJ_CASE_INSENSITIVE, 0, 0};
  HANDLE hFile;
  IO_STATUS_BLOCK isb;
  if (NT_SUCCESS(NtCreateFile(&hFile,FILE_READ_DATA,&oa,&isb,0,0,FILE_SHARE_READ,FILE_OPEN,0,0,0))) {
    CloseHandle(hFile);
    return TRUE;
  } else
    return FALSE;
}
//Create or open file in current folder. Analogous to Win32 CreateFile.
//option: GENERIC_READ / GENERIC_WRITE.
//share: FILE_SHARE_READ / FILE_SHARE_WRITE / FILE_SHARE_DELETE. 0 for exclusive access.
//disposition: FILE_OPEN / FILE_OPEN_IF.
//Use FILE_OPEN instead of OPEN_EXISTING and FILE_OPEN_IF for CREATE_ALWAYS.
HANDLE IthCreateFile(LPCWSTR name, DWORD option, DWORD share, DWORD disposition)
{
  UNICODE_STRING us;
  RtlInitUnicodeString(&us, name);
  OBJECT_ATTRIBUTES oa = { sizeof(oa), dir_obj, &us, OBJ_CASE_INSENSITIVE, 0, 0 };
  HANDLE hFile;
  IO_STATUS_BLOCK isb;
  return NT_SUCCESS(NtCreateFile(&hFile,
      option|FILE_READ_ATTRIBUTES|SYNCHRONIZE,
      &oa,&isb,0,0,share,disposition,
      FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE,0,0)) ?
    hFile : INVALID_HANDLE_VALUE;
}
//Create a directory file in current folder.
HANDLE IthCreateDirectory(LPCWSTR name)
{
  UNICODE_STRING us;
  RtlInitUnicodeString(&us,name);
  OBJECT_ATTRIBUTES oa = {sizeof(oa), dir_obj, &us, OBJ_CASE_INSENSITIVE, 0, 0};
  HANDLE hFile;
  IO_STATUS_BLOCK isb;
  return NT_SUCCESS(NtCreateFile(&hFile,FILE_LIST_DIRECTORY|FILE_TRAVERSE|SYNCHRONIZE,&oa,&isb,0,0,
      FILE_SHARE_READ|FILE_SHARE_WRITE,FILE_OPEN_IF,FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT,0,0)) ?
     hFile : INVALID_HANDLE_VALUE;
}

HANDLE IthCreateFileInDirectory(LPCWSTR name, HANDLE dir, DWORD option, DWORD share, DWORD disposition)
{
  UNICODE_STRING us;
  RtlInitUnicodeString(&us,name);
  if (dir == 0) dir = dir_obj;
  OBJECT_ATTRIBUTES oa = {sizeof(oa), dir, &us, OBJ_CASE_INSENSITIVE, 0, 0};
  HANDLE hFile;
  IO_STATUS_BLOCK isb;
  return NT_SUCCESS(NtCreateFile(&hFile,
      option|FILE_READ_ATTRIBUTES|SYNCHRONIZE,
      &oa,&isb,0,0,share,disposition,
      FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE,0,0)) ?
    hFile : INVALID_HANDLE_VALUE;
}

//Create section object for sharing memory between processes.
//Similar to CreateFileMapping.
HANDLE IthCreateSection(LPCWSTR name, DWORD size, DWORD right)
{
// jichi 9/25/2013: GENERIC_ALL does NOT work one wine
// See ZwCreateSection: http://msdn.microsoft.com/en-us/library/windows/hardware/ff566428%28v=vs.85%29.aspx
//#ifdef ITH_WINE
  enum { DesiredAccess = SECTION_ALL_ACCESS };
//#else
//  enum { DesiredAccess = GENERIC_ALL }; // jichi 9/25/2013: not sure whhy ITH is usin GENERIC_ALL
//#endif // ITH_WINE
#define eval    (NT_SUCCESS(NtCreateSection(&hSection, DesiredAccess, poa, &s, \
      right, SEC_COMMIT, 0)) ? hSection : INVALID_HANDLE_VALUE)
  HANDLE hSection;
  LARGE_INTEGER s = {size, 0};
  OBJECT_ATTRIBUTES *poa = nullptr;
  // jichi 9/25/2013: What the fxxx?! poa in the orignal source code of ITH
  // is pointed to freed object on the stack?! This will crash wine!
  if (name) {
    UNICODE_STRING us;
    RtlInitUnicodeString(&us, name);
    OBJECT_ATTRIBUTES oa = {sizeof(oa), root_obj, &us,OBJ_OPENIF,0,0};
    poa = &oa;
    return eval;
  } else
    return eval;
#undef retval
}

//Create event object. Similar to CreateEvent.
HANDLE IthCreateEvent(LPCWSTR name, DWORD auto_reset, DWORD init_state)
{
#define eval  (NT_SUCCESS(NtCreateEvent(&hEvent, EVENT_ALL_ACCESS, poa, auto_reset, init_state)) ? \
     hEvent : INVALID_HANDLE_VALUE)
  HANDLE hEvent;
  OBJECT_ATTRIBUTES *poa = nullptr;
  // jichi 9/25/2013: What the fxxx?! poa in the orignal source code of ITH
  // is pointed to freed object on the stack?! This will crash wine!
  if (name) {
    UNICODE_STRING us;
    RtlInitUnicodeString(&us,name);
    OBJECT_ATTRIBUTES oa = {sizeof(oa), root_obj, &us, OBJ_OPENIF, 0, 0};
    poa = &oa;
    return eval;
  } else
    return eval;
#undef eval
}

HANDLE IthOpenEvent(LPCWSTR name)
{
  UNICODE_STRING us;
  RtlInitUnicodeString(&us, name);
  OBJECT_ATTRIBUTES oa = { sizeof(oa), root_obj, &us, 0, 0, 0 };
  HANDLE hEvent;
  return NT_SUCCESS(NtOpenEvent(&hEvent, EVENT_ALL_ACCESS, &oa)) ?
     hEvent : INVALID_HANDLE_VALUE;
}

//Create mutex object. Similar to CreateMutex.
//If 'exist' is not null, it will be written 1 if mutex exist.
HANDLE IthCreateMutex(LPCWSTR name, BOOL InitialOwner, DWORD *exist)
{
  HANDLE ret = ::CreateMutexW(nullptr, InitialOwner, name);
  if (exist)
    *exist = ret == INVALID_HANDLE_VALUE || ::GetLastError() == ERROR_ALREADY_EXISTS;
  return ret;

}

HANDLE IthOpenMutex(LPCWSTR name)
{
  return ::OpenMutexW(MUTEX_ALL_ACCESS, FALSE, name);
}

HANDLE IthOpenPipe(LPWSTR name, ACCESS_MASK direction)
{
	return CreateFileW(name, direction, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

HANDLE IthCreateRemoteThread(LPCVOID start_addr, DWORD param)
{
	HANDLE hThread = CreateRemoteThread(GetCurrentProcess(), nullptr, 0, (LPTHREAD_START_ROUTINE)start_addr, (LPVOID)param, 0, nullptr);	
	return hThread ? hThread : INVALID_HANDLE_VALUE;
}

//Query module export table. Return function address if found.
//Similar to GetProcAddress
DWORD GetExportAddress(DWORD hModule,DWORD hash)
{
  IMAGE_DOS_HEADER *DosHdr;
  IMAGE_NT_HEADERS *NtHdr;
  IMAGE_EXPORT_DIRECTORY *ExtDir;
  UINT uj;
  char* pcExportAddr,*pcFuncPtr,*pcBuffer;
  DWORD dwReadAddr,dwFuncAddr,dwFuncName;
  WORD wOrd;
  DosHdr = (IMAGE_DOS_HEADER*)hModule;
  if (IMAGE_DOS_SIGNATURE==DosHdr->e_magic) {
    dwReadAddr=hModule+DosHdr->e_lfanew;
    NtHdr=(IMAGE_NT_HEADERS*)dwReadAddr;
    if (IMAGE_NT_SIGNATURE == NtHdr->Signature) {
      pcExportAddr = (char*)((DWORD)hModule+
          (DWORD)NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
      if (!pcExportAddr)
        return 0;
      ExtDir = (IMAGE_EXPORT_DIRECTORY*)pcExportAddr;
      pcExportAddr = (char*)((DWORD)hModule+(DWORD)ExtDir->AddressOfNames);

      for (uj = 0; uj < ExtDir->NumberOfNames; uj++) {
        dwFuncName = *(DWORD *)pcExportAddr;
        pcBuffer = (char*)((DWORD)hModule+dwFuncName);
        if (GetHash(pcBuffer) == hash) {
          pcFuncPtr = (char*)((DWORD)hModule+(DWORD)ExtDir->AddressOfNameOrdinals+(uj*sizeof(WORD)));
          wOrd = *(WORD*)pcFuncPtr;
          pcFuncPtr = (char*)((DWORD)hModule+(DWORD)ExtDir->AddressOfFunctions+(wOrd*sizeof(DWORD)));
          dwFuncAddr = *(DWORD *)pcFuncPtr;
          return hModule+dwFuncAddr;
        }
        pcExportAddr += sizeof(DWORD);
      }
    }
  }
  return 0;
}

} // extern "C"