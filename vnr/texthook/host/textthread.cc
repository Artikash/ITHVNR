// textthread.cc
// 8/24/2013 jichi
// Branch IHF/TextThread.cpp, rev 133
// 8/24/2013 TODO: Clean up this file

#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
#endif // _MSC_VER

#include "settings.h"
#include "textthread.h"
#include "vnrhook/include/const.h"
#include "ithsys/ithsys.h"
#include <stdio.h>
#include "growl.h";

MK_BASIC_TYPE(BYTE)
MK_BASIC_TYPE(ThreadParameter)

static DWORD MIN_DETECT = 0x20;
static DWORD MIN_REDETECT = 0x80;
//#define MIN_DETECT    0x20
//#define MIN_REDETECT  0x80
#ifndef CURRENT_SELECT
# define CURRENT_SELECT        0x1000
#endif
#ifndef REPEAT_NUMBER_DECIDED
# define REPEAT_NUMBER_DECIDED  0x2000
#endif

DWORD GetHookName(LPSTR str, DWORD pid, DWORD hook_addr,DWORD max);

extern Settings *settings;
extern HWND hMainWnd;

TextThread::TextThread(DWORD id, DWORD hook, DWORD retn, DWORD spl, WORD num) :
  //,tp
  thread_number(num)
  // jichi 9/21/2013: zero all fields
  , link_number(-1)
  , last (0)
  , align_space(0)
  , repeat_single(0)
  , repeat_single_current(0)
  , repeat_single_count(0)
  , repeat_detect_count(0)
  , head(new RepeatCountNode())
  , link(nullptr)
  //, filter(nullptr)
  , output(nullptr)
  , app_data(nullptr)
  //, comment(nullptr)
  , thread_string(nullptr)
  , timer(0)
  , status (0)
  , repeat_detect_limit(0x80)
  , last_sentence(0)
  , prev_sentence(0)
  , sentence_length(0)
  , repeat_index(0)
  , last_time(0)
{
  tp.pid = id;
  tp.hook = hook;
  tp.retn = retn;
  tp.spl = spl;
}
TextThread::~TextThread()
{
  //KillTimer(hMainWnd,timer);
  RepeatCountNode *t = head,
                  *tt;
  while (t) {
    tt = t;
    t = tt->next;
    delete tt;
  }
  head = nullptr;
  //if (comment) {
  //  delete[] comment;
  //  comment = nullptr;
  //}
  if (thread_string)
    delete[] thread_string;
}
void TextThread::Reset()
{
  //timer=0;
  last_sentence = 0;
  //if (comment) {
  //  delete[] comment;
  //  comment = nullptr;
  //}
  MyVector::Reset();
}

void TextThread::AddText(const BYTE *con, int len, bool space)
{
  if (!con || (len <= 0 && !space))
    return;

  if (len && sentence_length == 0) {
    if (status & USING_UNICODE) {
      if (*(WORD *)con == 0x3000) { // jichi 10/27/2013: why skip unicode space?!
        con += 2;
        len -= 2;
      }
    } else if (*(WORD *)con == 0x4081) {
      con += 2;
      len -= 2;
    }

    if (len <= 0 && !space)
      return;
  }

  if (len)
    {
      sentence_length += len;
    }

  BYTE *data = const_cast<BYTE *>(con); // jichi 10/27/2013: TODO: Figure out where con is modified
  if (output)
  {
	  len = output(this, data, len, false, app_data, space);
  }
    
  AddToStore(data, len);
}

void TextThread::AddTextDirect(const BYTE* con, int len, bool space) // Add to store directly, penetrating repetition filters.
{
  // jichi 10/27/2013: Accordig to the logic, both len and con must be > 0
  sentence_length += len;

  BYTE *data = const_cast<BYTE *>(con); // jichi 10/27/2013: TODO: Figure out where con is modified
  if (output)
    len = output(this, data, len, false, app_data, space);
  AddToStore(data, len);
}

DWORD TextThread::GetEntryString(LPSTR str, DWORD max)
{
  DWORD len = 0;
  if (str && max > 0x40) {
    max--;
    if (thread_string) {
      len = ::strlen(thread_string);
      len = len < max ? len : max;
      memcpy(str, thread_string, len);
      str[len] = 0;

    } else {
      len = ::sprintf(str, "%.4X:%.4d:0x%08X:0x%08X:0x%08X:",
          thread_number, tp. pid, tp.hook, tp.retn, tp.spl);

      len += GetHookName(str + len, tp.pid, tp.hook, max - len);
      thread_string = new char[len + 1];
      //::memset(thread_string, 0, (len+1) * sizeof(wchar_t)); // jichi 9/26/2013: zero memory
      thread_string[len] = 0;
      ::memcpy(thread_string, str, len);
    }
  }
  return len;
}

// EOF
