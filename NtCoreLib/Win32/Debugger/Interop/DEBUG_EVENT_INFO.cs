//  Copyright 2019 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Debugger.Interop;

[StructLayout(LayoutKind.Explicit)]
internal struct DEBUG_EVENT_INFO
{
    [FieldOffset(0)]
    public EXCEPTION_DEBUG_INFO Exception;
    [FieldOffset(0)]
    public CREATE_THREAD_DEBUG_INFO CreateThread;
    [FieldOffset(0)]
    public CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;
    [FieldOffset(0)]
    public EXIT_THREAD_DEBUG_INFO ExitThread;
    [FieldOffset(0)]
    public EXIT_PROCESS_DEBUG_INFO ExitProcess;
    [FieldOffset(0)]
    public LOAD_DLL_DEBUG_INFO LoadDll;
    [FieldOffset(0)]
    public UNLOAD_DLL_DEBUG_INFO UnloadDll;
    [FieldOffset(0)]
    public OUTPUT_DEBUG_STRING_INFO DebugString;
    [FieldOffset(0)]
    public RIP_INFO RipInfo;
}
