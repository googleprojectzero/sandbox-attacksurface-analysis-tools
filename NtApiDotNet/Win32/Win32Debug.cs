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

using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32
{
#pragma warning disable 1591
    [StructLayout(LayoutKind.Sequential)]
    public struct CreateThreadDebugInfo
    {
        public IntPtr hThread;
        public IntPtr lpThreadLocalBase;
        public IntPtr lpStartAddress;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CreateProcessDebugInfo
    {
        public IntPtr hFile;
        public IntPtr hProcess;
        public IntPtr hThread;
        public IntPtr lpBaseOfImage;
        public int dwDebugInfoFileOffset;
        public int nDebugInfoSize;
        public IntPtr lpThreadLocalBase;
        public IntPtr lpStartAddress;
        public IntPtr lpImageName;
        public short fUnicode;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ExitThreadDebugInfo
    {
        public int dwExitCode;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ExitProcessDebugInfo
    {
        public int dwExitCode;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LoadDllDebugInfo
    {
        public IntPtr hFile;
        public IntPtr lpBaseOfDll;
        public int dwDebugInfoFileOffset;
        public int nDebugInfoSize;
        public IntPtr lpImageName;
        public short fUnicode;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UnloadDllDebugInfo
    {
        public IntPtr lpBaseOfDll;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OutputDebugStringInfo
    {
        public IntPtr lpDebugStringData;
        public short fUnicode;
        public short nDebugStringLength;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct DebugEventInfo
    {
        [FieldOffset(0)]
        public ExceptionDebugInfo Exception;
        [FieldOffset(0)]
        public CreateThreadDebugInfo CreateThread;
        [FieldOffset(0)]
        public CreateProcessDebugInfo CreateProcessInfo;
        [FieldOffset(0)]
        public ExitThreadDebugInfo ExitThread;
        [FieldOffset(0)]
        public ExitProcessDebugInfo ExitProcess;
        [FieldOffset(0)]
        public LoadDllDebugInfo LoadDll;
        [FieldOffset(0)]
        public UnloadDllDebugInfo UnloadDll;
        [FieldOffset(0)]
        public OutputDebugStringInfo DebugString;
        [FieldOffset(0)]
        public RipInfo RipInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DebugEventStruct
    {
        public DebugEventCode dwDebugEventCode;
        public int dwProcessId;
        public int dwThreadId;
        public DebugEventInfo Info;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ExceptionDebugInfo
    {
        public ExceptionRecord ExceptionRecord;
        public int dwFirstChance;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RipInfo
    {
        public int dwError;
        public int dwType;
    }

    public enum DebugEventCode
    {
        Unknown = 0,
        Exception = 1,
        CreateThread = 2,
        CreateProcess = 3,
        ExitThread = 4,
        ExitProcess = 5,
        LoadDll = 6,
        UnloadDll = 7,
        OutputDebugString = 8,
        Rip = 9
    }
#pragma warning restore 1591
}
