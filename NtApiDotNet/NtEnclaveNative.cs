//  Copyright 2020 Google Inc. All Rights Reserved.
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

    /// <summary>
    /// Type of enclave.
    /// </summary>
    public enum LdrEnclaveType
    {
        SGX = 1,
        SGX2 = 2,
        VBS = 0x10,
        VBS_BASIC = 0x11
    }

    [Flags]
    public enum LdrEnclaveVBSFlags
    {
        None = 0,
        Debug = 1,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EnclaveCreateInfoVBS
    {
        public LdrEnclaveVBSFlags Flags;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] OwnerID;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EnclaveInitInfoVBS
    {
        public int Length;
        public int ThreadCount;
    }

    public static partial class NtLdrNative
    {
        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus LdrCreateEnclave(
            SafeKernelObjectHandle ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr Size,
            IntPtr InitialCommitment,
            LdrEnclaveType EnclaveType,
            SafeBuffer EnclaveInformation,
            int EnclaveInformationLength,
            out int EnclaveError);

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus LdrInitializeEnclave(
            SafeKernelObjectHandle ProcessHandle,
            SafeHandle BaseAddress,
            SafeBuffer EnclaveInformation,
            int EnclaveInformationLength,
            out int EnclaveError
        );

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus LdrLoadEnclaveData(
            SafeKernelObjectHandle ProcessHandle,
            SafeHandle BaseAddress,
            IntPtr Buffer,
            IntPtr BufferSize,
            MemoryAllocationProtect Protect,
            SafeBuffer PageInformation,
            int PageInformationLength,
            out IntPtr NumberOfBytesWritten,
            out int EnclaveError
        );

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus LdrLoadEnclaveModule(
            SafeHandle BaseAddress,
            IntPtr Flags,
            UnicodeString ModuleName
        );

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus LdrCallEnclave(IntPtr EnclaveRoutine, 
            [MarshalAs(UnmanagedType.U1)] bool WaitForThread, ref IntPtr Parameter);

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus LdrDeleteEnclave(IntPtr BaseAddress);
    }

    public enum TerminateEnclaveFlags
    {
        None = 0,
        WaitForThreads = 1,
        CheckForTerminate = 4,
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus NtTerminateEnclave(
            SafeHandle BaseAddress,
            TerminateEnclaveFlags Flags
        );
    }
#pragma warning restore 1591
}
