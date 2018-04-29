#pragma once

// engine/match.h
// 8/23/2013 jichi
// TODO: Clean up the interface to match game engines.
// Split the engine match logic out of hooks.
// Modify the game hook to allow replace functions for arbitary purpose
// instead of just extracting text.

#include <windows.h>

namespace Engine {

// jichi 10/21/2014: Return whether found the engine
void hijack();
void terminate();

/** jichi 12/24/2014
*  @param  addr  function address
*  @param  frame  real address of the function, supposed to be the same as addr
*  @param  stack  address of current stack - 4
*  @return  If success, which is reverted
*/
DWORD InsertDynamicHook(LPVOID addr, DWORD frame, DWORD stack);

} // namespace Engine

// EOF
