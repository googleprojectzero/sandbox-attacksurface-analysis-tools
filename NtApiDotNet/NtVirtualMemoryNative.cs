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

namespace NtApiDotNet
{
#pragma warning disable 1591
    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtReadVirtualMemory(SafeKernelObjectHandle ProcessHandle,
            IntPtr BaseAddress, SafeBuffer Buffer, int BufferLength, out int ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtWriteVirtualMemory(SafeKernelObjectHandle ProcessHandle,
            IntPtr BaseAddress, SafeBuffer Buffer, int BufferLength, out int ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryVirtualMemory(
          SafeKernelObjectHandle ProcessHandle,
          IntPtr BaseAddress,
          MemoryInformationClass MemoryInformationClass,
          SafeBuffer MemoryInformation,
          IntPtr MemoryInformationLength,
          out IntPtr ReturnLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtFlushVirtualMemory(
          SafeKernelObjectHandle ProcessHandle,
          ref IntPtr BaseAddress,
          ref IntPtr RegionSize,
          out IoStatus IoStatus
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAllocateVirtualMemory(
          SafeKernelObjectHandle ProcessHandle,
          ref IntPtr BaseAddress,
          IntPtr ZeroBits,
          ref IntPtr RegionSize,
          MemoryAllocationType AllocationType,
          MemoryAllocationProtect Protect
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAllocateVirtualMemoryEx(
            SafeKernelObjectHandle ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            MemoryAllocationType AllocationType,
            MemoryAllocationProtect Protect,
            MemExtendedParameter[] ExtendedParameters,
            int ExtendedParameterCount
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtFreeVirtualMemory(
            SafeKernelObjectHandle ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            MemoryFreeType FreeType
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtProtectVirtualMemory(
            SafeKernelObjectHandle ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            MemoryAllocationProtect NewProtect,
            out MemoryAllocationProtect OldProtect
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAreMappedFilesTheSame(
            IntPtr Mapped1,
            IntPtr Mapped2
        );
    }

    [Flags]
    public enum MemoryAllocationProtect
    {
        None = 0,
        NoAccess = 0x01,
        ReadOnly = 0x02,
        ReadWrite = 0x04,
        WriteCopy = 0x08,
        Execute = 0x10,
        ExecuteRead = 0x20,
        ExecuteReadWrite = 0x40,
        ExecuteWriteCopy = 0x80,
        Guard = 0x100,
        NoCache = 0x200,
        WriteCombine = 0x400,
    }

    [Flags]
    public enum MemoryState : uint
    {
        Commit = 0x1000,
        Reserve = 0x2000,
        Free = 0x10000,
    }

    [Flags]
    public enum MemoryAllocationType : uint
    {
        Commit = 0x1000,
        Reserve = 0x2000,
        Reset = 0x80000,
        TopDown = 0x100000,
        Physical = 0x400000,
        ResetUndo = 0x1000000,
        LargePages = 0x20000000,
        WriteWatch = 0x200000,
        FourMBPages = 0x80000000,
    }

    [Flags]
    public enum MemoryFreeType : uint
    {
        Decommit = 0x4000,
        Release = 0x8000
    }

    [Flags]
    public enum MemoryType
    {
        None = 0,
        Private = 0x20000,
        Mapped = 0x40000,
        Image = 0x1000000,
        All = Private | Mapped | Image
    }

    public enum MemoryInformationClass
    {
        MemoryBasicInformation,
        MemoryWorkingSetInformation,
        MemoryMappedFilenameInformation,
        MemoryRegionInformation,
        MemoryWorkingSetExInformation,
        MemorySharedCommitInformation,
        MemoryImageInformation,
        MemoryRegionInformationEx,
        MemoryPrivilegedBasicInformation,
        MemoryEnclaveImageInformation,
        MemoryBasicInformationCapped
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MemoryBasicInformation
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public MemoryAllocationProtect AllocationProtect;
        public IntPtr RegionSize;
        public MemoryState State;
        public MemoryAllocationProtect Protect;
        public MemoryType Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MemoryWorkSetExBlock
    {
        private IntPtr _flags;
        public long Flags => _flags.ToInt64();
        public bool Valid => Flags.GetBit(0);
        public long ShareCount => Flags.GetBits(1, 3);
        public MemoryAllocationProtect Win32Protection => (MemoryAllocationProtect)Flags.GetBits(4, 11);
        public bool Shared => Flags.GetBit(15);
        public long Node => Flags.GetBits(16, 6);
        public bool Locked => Flags.GetBit(22);
        public bool Bad => Flags.GetBit(31);
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MemoryWorkingSetExInformation
    {
        public IntPtr VirtualAddress;
        public MemoryWorkSetExBlock VirtualAttributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MemoryImageInformation
    {
        public IntPtr ImageBase;
        public IntPtr SizeOfImage;
        public int ImageFlags;

        public bool PartialMap => ImageFlags.GetBit(0);
        public bool NotExecutable => ImageFlags.GetBit(1);
        public SigningLevel ImageSigningLevel => (SigningLevel)ImageFlags.GetBits(2, 4);
    }

#pragma warning restore 1591
}
