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

using NtApiDotNet.Utilities.Reflection;
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

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtFlushInstructionCache(
            SafeKernelObjectHandle ProcessHandle,
            IntPtr BaseAddress,
            int NumberOfBytesToFlush);
    }

    [Flags]
    public enum MemoryAllocationProtect : uint
    {
        [SDKName("NONE")]
        None = 0,
        [SDKName("PAGE_NOACCESS")]
        NoAccess = 0x01,
        [SDKName("PAGE_READONLY")]
        ReadOnly = 0x02,
        [SDKName("PAGE_READWRITE")]
        ReadWrite = 0x04,
        [SDKName("PAGE_WRITECOPY")]
        WriteCopy = 0x08,
        [SDKName("PAGE_EXECUTE")]
        Execute = 0x10,
        [SDKName("PAGE_EXECUTE_READ")]
        ExecuteRead = 0x20,
        [SDKName("PAGE_EXECUTE_READWRITE")]
        ExecuteReadWrite = 0x40,
        [SDKName("PAGE_EXECUTE_WRITECOPY")]
        ExecuteWriteCopy = 0x80,
        [SDKName("PAGE_GUARD")]
        Guard = 0x100,
        [SDKName("PAGE_NOCACHE")]
        NoCache = 0x200,
        [SDKName("PAGE_WRITECOMBINE")]
        WriteCombine = 0x400,
        [SDKName("PAGE_GRAPHICS_NOACCESS")]
        GraphicsNoAccess = 0x800,
        [SDKName("PAGE_GRAPHICS_READONLY")]
        GraphicsReadOnly = 0x1000,
        [SDKName("PAGE_GRAPHICS_READWRITE")]
        GraphicsReadWrite = 0x2000,
        [SDKName("PAGE_GRAPHICS_EXECUTE")]
        GraphicsExecute = 0x4000,
        [SDKName("PAGE_GRAPHICS_EXECUTE_READ")]
        GraphicsExecuteRead = 0x8000,
        [SDKName("PAGE_GRAPHICS_EXECUTE_READWRITE")]
        GraphicsExecuteReadWrite = 0x10000,
        [SDKName("PAGE_GRAPHICS_COHERENT")]
        GraphicsCoherent = 0x20000,
        [SDKName("PAGE_GRAPHICS_NOCACHE")]
        GraphicsNoCache = 0x40000,
        [SDKName("PAGE_ENCLAVE_THREAD_CONTROL")]
        EnclaveThreadControl = 0x80000000,
        [SDKName("PAGE_REVERT_TO_FILE_MAP")]
        RevertToFileMap = 0x80000000,
        [SDKName("PAGE_TARGETS_NO_UPDATE")]
        TargetsNoUpdate = 0x40000000,
        [SDKName("PAGE_TARGETS_INVALID")]
        TargetsInvalid = 0x40000000,
        [SDKName("PAGE_ENCLAVE_UNVALIDATED")]
        EnclaveUnvalidated = 0x20000000,
        [SDKName("PAGE_ENCLAVE_DECOMMIT")]
        EnclaveDecommit = 0x10000000,
        [SDKName("PAGE_ENCLAVE_SS_FIRST")]
        EnclaveSSFirst = 0x10000001,
        [SDKName("PAGE_ENCLAVE_SS_REST")]
        EnclaveSSRest = 0x10000002
    }

    [Flags]
    public enum MemoryState : uint
    {
        [SDKName("MEM_COMMIT")]
        Commit = 0x1000,
        [SDKName("MEM_RESERVE")]
        Reserve = 0x2000,
        [SDKName("MEM_FREE")]
        Free = 0x10000,
        All = Commit | Reserve | Free
    }

    [Flags]
    public enum MemoryAllocationType : uint
    {
        [SDKName("MEM_COMMIT")]
        Commit = 0x1000,
        [SDKName("MEM_RESERVE")]
        Reserve = 0x2000,
        [SDKName("MEM_RESET")]
        Reset = 0x80000,
        [SDKName("MEM_TOP_DOWN")]
        TopDown = 0x100000,
        [SDKName("MEM_WRITE_WATCH")]
        WriteWatch = 0x200000,
        [SDKName("MEM_PHYSICAL")]
        Physical = 0x400000,
        [SDKName("MEM_ROTATE")]
        Rotate = 0x800000,
        [SDKName("MEM_DIFFERENT_IMAGE_BASE_OK")]
        DifferentImagePageOkay = 0x800000,
        [SDKName("MEM_RESET_UNDO")]
        ResetUndo = 0x1000000,
        [SDKName("MEM_LARGE_PAGES")]
        LargePages = 0x20000000,
        [SDKName("MEM_4MB_PAGES")]
        FourMBPages = 0x80000000,
    }

    [Flags]
    public enum MemoryFreeType : uint
    {
        [SDKName("MEM_DECOMMIT")]
        Decommit = 0x4000,
        [SDKName("MEM_RELEASE")]
        Release = 0x8000
    }

    [Flags]
    public enum MemoryType
    {
        None = 0,
        [SDKName("MEM_PRIVATE")]
        Private = 0x20000,
        [SDKName("MEM_MAPPED")]
        Mapped = 0x40000,
        [SDKName("MEM_IMAGE")]
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
        MemoryBasicInformationCapped,
        MemoryPhysicalContiguityInformation,
    }

    [StructLayout(LayoutKind.Sequential), SDKName("MEMORY_BASIC_INFORMATION")]
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

    [StructLayout(LayoutKind.Sequential), SDKName("MEMORY_WORKING_SET_EX_BLOCK")]
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

    [StructLayout(LayoutKind.Sequential), SDKName("MEMORY_WORKING_SET_EX_LOCATION")]
    public struct MemoryWorkingSetExInformation
    {
        public IntPtr VirtualAddress;
        public MemoryWorkSetExBlock VirtualAttributes;
    }

    [StructLayout(LayoutKind.Sequential), SDKName("MEMORY_IMAGE_INFORMATION")]
    public struct MemoryImageInformation
    {
        public IntPtr ImageBase;
        public IntPtr SizeOfImage;
        public int ImageFlags;

        public bool PartialMap => ImageFlags.GetBit(0);
        public bool NotExecutable => ImageFlags.GetBit(1);
        public SigningLevel ImageSigningLevel => (SigningLevel)ImageFlags.GetBits(2, 4);
    }

    [Flags]
    public enum MemoryRegionTypeFlags
    {
        None = 0,
        Private = 1,
        MappedDataFile = 2,
        MappedImage = 4,
        MappedPageFile = 8,
        MappedPhysical = 0x10,
        DirectMapped = 0x20,
        SoftwareEnclave = 0x40,
        PageSize64K = 0x80,
        PlaceholderReservation = 0x100
    }

    [StructLayout(LayoutKind.Sequential), SDKName("MEMORY_REGION_INFORMATION")]
    public struct MemoryRegionInformation
    {
        public IntPtr AllocationBase;
        public MemoryAllocationProtect AllocationProtect;
        public MemoryRegionTypeFlags RegionType;
        public IntPtr RegionSize;
        public IntPtr CommitSize;
        public IntPtr PartitionId;
        public IntPtr NodePreference;
    }

#pragma warning restore 1591
}
