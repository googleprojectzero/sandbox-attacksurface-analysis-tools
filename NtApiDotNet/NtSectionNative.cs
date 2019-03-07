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

    [Flags]
    public enum SectionAttributes : uint
    {
        None = 0,
        PartitionOwnerHandle = 0x00040000,
        Pages64k = 0x00080000,
        Unknown100000 = 0x00100000,
        Based = 0x00200000,
        NoChange = 0x00400000,
        File = 0x00800000,
        Image = 0x01000000,
        ProtectedImage = 0x02000000,
        Reserve = 0x04000000,
        Commit = 0x08000000,
        NoCache = 0x10000000,
        WriteCombine = 0x40000000,
        LargePages = 0x80000000,
        ImageNoExecute = Image | NoCache
    }

    [Flags]
    public enum SectionAccessRights : uint
    {
        Query = 0x0001,
        MapWrite = 0x0002,
        MapRead = 0x0004,
        MapExecute = 0x0008,
        ExtendSize = 0x0010,
        MapExecuteExplicit = 0x0020,
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
    public enum ImageCharacteristics : ushort
    {
        None = 0,
        RelocsStripped = 0x0001,
        ExecutableImage = 0x0002,
        LineNumsStripped = 0x0004,
        LocalSymsStripped = 0x0008,
        AggresiveWsTrim = 0x0010,
        LargeAddressAware = 0x0020,
        FileBytesReservedLo = 0x0080,
        Image32BitMachine = 0x0100,
        DebugStripped = 0x0200,
        RemovableRunFromSwap = 0x0400,
        NetRunFromSwap = 0x0800,
        System = 0x1000,
        Dll = 0x2000,
        UpSystemOnly = 0x4000,
        BytesReservedHi = 0x8000,
    }

    public enum SectionInherit
    {
        ViewShare = 1,
        ViewUnmap = 2
    }

    [Flags]
    public enum AllocationType
    {
        None = 0,
        Commit = 0x00001000,
        Reserve = 0x00002000,
        ReplacePlaceholder = 0x00004000,
        Reset = 0x00080000,
        ResetUndo = 0x1000000,
        LargePages = 0x20000000,
        Physical = 0x00400000,
        TopDown = 0x00100000,
        WriteWatch = 0x00200000,
    }

    [Flags]
    public enum MemUnmapFlags
    {
        None = 0,
        WriteTransientBoost = 0x00000001,
        PreservePlaceholder = 0x00000002
    }

    public enum SectionInformationClass
    {
        SectionBasicInformation,
        SectionImageInformation,
        SectionRelocationInformation,
        SectionOriginalBaseInformation,
        SectionInternalImageInformation
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SectionBasicInformation
    {
        public IntPtr BaseAddress;
        public SectionAttributes Attributes;
        public LargeIntegerStruct Size;
    }

    [Flags]
    public enum SectionImageFlags : byte
    {
        ComPlusNativeReady = 1,
        ComPlusILOnly = 2,
        ImageDynamicallyRelocated = 4,
        ImageMappedFlat = 8,
        BaseBelow4gb = 16,
        ComPlusPrefer32bit = 32
    }

    public enum DllMachineType : ushort
    {
        UNKNOWN = 0x0,
        AM33 = 0x13,
        AMD64 = 0x8664,
        ARM = 0x1C0,
        ARMV7 = 0x1C4,
        EBC = 0xEBC,
        I386 = 0x14C,
        IA64 = 0x200,
        M32R = 0x9041,
        MIPS16 = 0x266,
        MIPSFPU = 0x366,
        MIPSFPU16 = 0x466,
        POWERPC = 0x1F0,
        POWERPCFP = 0x1F1,
        R4000 = 0x166,
        SH3 = 0x1A2,
        SH3DSP = 0x1A3,
        SH4 = 0x1A6,
        SH5 = 0x1A8,
        THUMB = 0x1C2,
        WCEMIPSV2 = 0x169,
        ARM64 = 0xAA64,
    }

    [Flags]
    public enum DllCharacteristics : ushort
    {
        None = 0,
        Reserved0001 = 0x0001,
        Reserved0002 = 0x0002,
        Reserved0004 = 0x0004,
        Reserved0008 = 0x0008,
        Reserved0010 = 0x0010,
        HighEntropyVA = 0x0020,
        DynamicBase = 0x0040,
        ForceIntegrity = 0x0080,
        NXCompat = 0x0100,
        NoIsolation = 0x0200,
        NoSEH = 0x0400,
        NoBind = 0x0800,
        AppContainer = 0x1000,
        WDMDriver = 0x2000,
        GuardCF = 0x4000,
        TerminalServerAware = 0x8000,
    }

    public enum ImageSubsystemType
    {
        Unknown = 0,
        Native = 1,
        WindowsGUI = 2,
        WindowsCUI = 3,
        OS2CUI = 5,
        POSIXCUI = 7,
        NativeWindows = 8,
        WindowsCEGUI = 9,
        EFIApplication = 10,
        EFIBootServiceDriver = 11,
        EFIRuntimeDriver = 12,
        EFIRom = 13,
        XBOX = 14,
        WindowsBootApplication = 16
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SectionImageInformation
    {
        public IntPtr TransferAddress;
        public uint ZeroBits;
        public IntPtr MaximumStackSize;
        public IntPtr CommittedStackSize;
        public ImageSubsystemType SubSystemType;
        public ushort SubSystemMinorVersion;
        public ushort SubSystemMajorVersion;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ImageCharacteristics ImageCharacteristics;
        public DllCharacteristics DllCharacteristics;
        public DllMachineType Machine;
        [MarshalAs(UnmanagedType.U1)]
        public bool ImageContainsCode;
        [MarshalAs(UnmanagedType.U1)]
        public SectionImageFlags ImageFlags;
        public uint LoaderFlags;
        public uint ImageFileSize;
        public uint CheckSum;
    }

    public enum MemExtendedParameterType : long
    {
        MemExtendedParameterInvalidType,
        MemExtendedParameterAddressRequirements,
        MemExtendedParameterNumaNode,
        MemExtendedParameterPartitionHandle,
        MemExtendedParameterUserPhysicalHandle,
        MemExtendedParameterAttributeFlags,
        MemExtendedParameterMax
    }

    public enum MemSectionExtendedParameterType
    {
        MemSectionExtendedParameterInvalidType,
        MemSectionExtendedParameterUserPhysicalFlags,
        MemSectionExtendedParameterNumaNode,
        MemSectionExtendedParameterMax
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct MemExtendedParameterValue
    {
        [FieldOffset(0)]
        public ulong ULong64;
        [FieldOffset(0)]
        public IntPtr Pointer;
        [FieldOffset(0)]
        public IntPtr Size;
        [FieldOffset(0)]
        public IntPtr Handle;
        [FieldOffset(0)]
        public uint ULong;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MemSectionExtendedParameter
    {
        public MemSectionExtendedParameterType Type;
        public MemExtendedParameterValue Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MemExtendedParameter
    {
        public MemExtendedParameterType Type;
        public MemExtendedParameterValue Value;
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateSection(out SafeKernelObjectHandle SectionHandle,
            SectionAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes, [In] LargeInteger SectionSize,
            MemoryAllocationProtect Protect, SectionAttributes Attributes,
            SafeHandle FileHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateSectionEx(out SafeKernelObjectHandle SectionHandle,
            SectionAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes, [In] LargeInteger SectionSize,
            MemoryAllocationProtect Protect, SectionAttributes Attributes,
            SafeHandle FileHandle,
            MemSectionExtendedParameter[] ExtendedParameters, int ExtendedParameterCount);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenSection(out SafeKernelObjectHandle SectionHandle,
            SectionAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQuerySection(SafeKernelObjectHandle SectionHandle,
             SectionInformationClass SectionInformationClass,
             SafeBuffer SectionInformation,
             int SectionInformationLength,
             out int ResultLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtMapViewOfSection(
            SafeKernelObjectHandle SectionHandle,
            SafeKernelObjectHandle ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            [In, Out] LargeInteger SectionOffset,
            ref IntPtr ViewSize,
            SectionInherit InheritDisposition,
            AllocationType AllocationType,
            MemoryAllocationProtect Win32Protect
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtMapViewOfSectionEx(
            SafeKernelObjectHandle SectionHandle,
            SafeKernelObjectHandle ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            [In, Out] LargeInteger SectionOffset,
            ref IntPtr ViewSize,
            SectionInherit InheritDisposition,
            AllocationType AllocationType,
            MemoryAllocationProtect Win32Protect,
            MemExtendedParameter[] ExtendedParameters,
            int ExtendedParameterCount
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtUnmapViewOfSection(
            SafeKernelObjectHandle ProcessHandle,
            IntPtr BaseAddress
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtUnmapViewOfSectionEx(
            SafeKernelObjectHandle ProcessHandle,
            IntPtr BaseAddress,
            MemUnmapFlags Flags
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtExtendSection(
            SafeKernelObjectHandle SectionHandle,
            [In, Out] LargeInteger SectionSize
        );
    }
#pragma warning restore 1591
}
