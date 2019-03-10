//  Copyright 2016 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet
{
#pragma warning disable 1591
    [Flags]
    public enum DebugAccessRights : uint
    {
        ReadEvent = 0x1,
        ProcessAssign = 0x2,
        SetInformation = 0x4,
        QueryInformation = 0x8,
        GenericRead = GenericAccessRights.GenericRead,
        GenericWrite = GenericAccessRights.GenericWrite,
        GenericExecute = GenericAccessRights.GenericExecute,
        GenericAll = GenericAccessRights.GenericAll,
        Delete = GenericAccessRights.Delete,
        ReadControl = GenericAccessRights.ReadControl,
        WriteDac = GenericAccessRights.WriteDac,
        WriteOwner = GenericAccessRights.WriteOwner,
        Synchronize = GenericAccessRights.Synchronize,
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
        AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
    }

    [Flags]
    public enum DebugObjectFlags
    {
        None = 0,
        KillOnClose = 1,
    }

    public enum DebugObjectInformationClass
    {
        DebugObjectKillProcessOnExitInformation = 1,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ExceptionRecord
    {
        public NtStatus ExceptionCode;
        public NtStatus ExceptionFlags;
        public IntPtr ExceptionRecordChain;
        public IntPtr ExceptionAddress;
        public int NumberParameters;
        public IntPtr ExceptionInformation0;
        public IntPtr ExceptionInformation1;
        public IntPtr ExceptionInformation2;
        public IntPtr ExceptionInformation3;
        public IntPtr ExceptionInformation4;
        public IntPtr ExceptionInformation5;
        public IntPtr ExceptionInformation6;
        public IntPtr ExceptionInformation7;
        public IntPtr ExceptionInformation8;
        public IntPtr ExceptionInformation9;
        public IntPtr ExceptionInformationA;
        public IntPtr ExceptionInformationB;
        public IntPtr ExceptionInformationC;
        public IntPtr ExceptionInformationD;
        public IntPtr ExceptionInformationE;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DbgKmException
    {
        public ExceptionRecord ExceptionRecord;
        public int FirstChance;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DbgKmCreateThread
    {
        public int SubSystemKey;
        public IntPtr StartAddress;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DbgKmCreateProcess
    {
        public int SubSystemKey;
        public IntPtr FileHandle;
        public IntPtr BaseOfImage;
        public int DebugInfoFileOffset;
        public int DebugInfoSize;
        public DbgKmCreateThread InitialThread;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DbgKmExitThread
    {
        public NtStatus ExitStatus;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DbgKmExitProcess
    {
        public NtStatus ExitStatus;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DbgKmLoadDll
    {
        public IntPtr FileHandle;
        public IntPtr BaseOfDll;
        public int DebugInfoFileOffset;
        public int DebugInfoSize;
        public IntPtr NamePointer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DbgKmUnloadDll
    {
        public IntPtr BaseAddress;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DbgUiCreateThread
    {
        public IntPtr HandleToThread;
        public DbgKmCreateThread NewThread;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DbgUiCreateProcess
    {
        public IntPtr HandleToProcess;
        public IntPtr HandleToThread;
        public DbgKmCreateProcess NewProcess;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct DbgUiStateInfo
    {
        [FieldOffset(0)]
        public DbgKmException Exception;
        [FieldOffset(0)]
        public DbgUiCreateThread CreateThread;
        [FieldOffset(0)]
        public DbgUiCreateProcess CreateProcess;
        [FieldOffset(0)]
        public DbgKmExitThread ExitThread;
        [FieldOffset(0)]
        public DbgKmExitProcess ExitProcess;
        [FieldOffset(0)]
        public DbgKmLoadDll LoadDll;
        [FieldOffset(0)]
        public DbgKmUnloadDll UnloadDll;
    }

    public enum DbgState
    {
        Idle,
        ReplyPending,
        CreateThreadStateChange,
        CreateProcessStateChange,
        ExitThreadStateChange,
        ExitProcessStateChange,
        ExceptionStateChange,
        BreakpointStateChange,
        SingleStepStateChange,
        LoadDllStateChange,
        UnloadDllStateChange
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DbgUiWaitStatusChange
    {
        public DbgState NewState;
        public ClientIdStruct AppClientId;
        public DbgUiStateInfo StateInfo;
    }

    public static class NtDbgUi
    {
        [DllImport("ntdll.dll")]
        public static extern IntPtr DbgUiGetThreadDebugObject();

        [DllImport("ntdll.dll")]
        public static extern void DbgUiSetThreadDebugObject(IntPtr DebugObjectHandle);
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtDebugActiveProcess(SafeKernelObjectHandle ProcessHandle, SafeKernelObjectHandle DebugObjectHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateDebugObject(out SafeKernelObjectHandle DebugObjectHandle,
            DebugAccessRights DesiredAccess, [In] ObjectAttributes ObjectAttributes, DebugObjectFlags Flags);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtDebugContinue(
            SafeKernelObjectHandle DebugObjectHandle,
            ClientId ClientId,
            NtStatus ContinueStatus
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRemoveProcessDebug(
            SafeKernelObjectHandle ProcessHandle, 
            SafeKernelObjectHandle DebugObjectHandle
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetInformationDebugObject(
            SafeKernelObjectHandle DebugObjectHandle,
            DebugObjectInformationClass DebugObjectInformationClass,
            SafeBuffer DebugInformation,
            int DebugInformationLength,
            out int ReturnLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtWaitForDebugEvent(
            SafeKernelObjectHandle DebugObjectHandle,
            bool Alertable,
            LargeInteger Timeout,
            SafeBuffer WaitStateChange
        );
    }
#pragma warning restore 1591
}
