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
    /// <summary>
    /// Generic access rights.
    /// </summary>
    [Flags]
    public enum GenericAccessRights : uint
    {
        None = 0,
        Access0 = 0x00000001,
        Access1 = 0x00000002,
        Access2 = 0x00000004,
        Access3 = 0x00000008,
        Access4 = 0x00000010,
        Access5 = 0x00000020,
        Access6 = 0x00000040,
        Access7 = 0x00000080,
        Access8 = 0x00000100,
        Access9 = 0x00000200,
        Access10 = 0x00000400,
        Access11 = 0x00000800,
        Access12 = 0x00001000,
        Access13 = 0x00002000,
        Access14 = 0x00004000,
        Access15 = 0x00008000,
        Delete = 0x00010000,
        ReadControl = 0x00020000,
        WriteDac = 0x00040000,
        WriteOwner = 0x00080000,
        Synchronize = 0x00100000,
        AccessSystemSecurity = 0x01000000,
        MaximumAllowed = 0x02000000,
        GenericAll = 0x10000000,
        GenericExecute = 0x20000000,
        GenericWrite = 0x40000000,
        GenericRead = 0x80000000,
    };

    /// <summary>
    /// Options for duplicating objects.
    /// </summary>
    [Flags]
    public enum DuplicateObjectOptions
    {
        None = 0,
        /// <summary>
        /// Close the original handle.
        /// </summary>
        CloseSource = 1,
        /// <summary>
        /// Duplicate with the same access.
        /// </summary>
        SameAccess = 2,
        /// <summary>
        /// Duplicate with the same handle attributes.
        /// </summary>
        SameAttributes = 4,
        /// <summary>
        /// Prevent duplicating handle above the existing access.
        /// </summary>
        NoRightsUpgrade = 8,
    }

    /// <summary>
    /// Information class for NtQueryObject
    /// </summary>
    /// <see cref="NtSystemCalls.NtQueryObject(SafeHandle, ObjectInformationClass, SafeBuffer, int, out int)"/>
    public enum ObjectInformationClass
    {
        ObjectBasicInformation,
        ObjectNameInformation,
        ObjectTypeInformation,
        ObjectTypesInformation,
        ObjectHandleFlagInformation,
        ObjectSessionInformation,
        ObjectSessionObjectInformation
    }

    /// <summary>
    /// Structure to return Object Name
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public class ObjectNameInformation
    {
        public UnicodeStringOut Name;
    }

    /// <summary>
    /// Structure to return Object basic information
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct ObjectBasicInformation
    {
        public AttributeFlags Attributes;
        public uint DesiredAccess;
        public int HandleCount;
        public int ReferenceCount;
        public int PagedPoolUsage;
        public int NonPagedPoolUsage;
        public int Reserved0;
        public int Reserved1;
        public int Reserved2;
        public int NameInformationLength;
        public int TypeInformationLength;
        public int SecurityDescriptorLength;
        public LargeIntegerStruct CreationTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ObjectHandleInformation
    {
        [MarshalAs(UnmanagedType.U1)]
        public bool Inherit;
        [MarshalAs(UnmanagedType.U1)]
        public bool ProtectFromClose;
    }

    /// <summary>
    /// Type of kernel pool used for object allocation
    /// </summary>
    public enum PoolType
    {
        NonPagedPool,
        PagedPool,
        NonPagedPoolMustSucceed,
        DontUseThisType,
        NonPagedPoolCacheAligned,
        PagedPoolCacheAligned,
        NonPagedPoolCacheAlignedMustS
    }

    /// <summary>
    /// Native structure used for getting type information.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct ObjectTypeInformation
    {
        public UnicodeStringOut Name;
        public uint TotalNumberOfObjects;
        public uint TotalNumberOfHandles;
        public uint TotalPagedPoolUsage;
        public uint TotalNonPagedPoolUsage;
        public uint TotalNamePoolUsage;
        public uint TotalHandleTableUsage;
        public uint HighWaterNumberOfObjects;
        public uint HighWaterNumberOfHandles;
        public uint HighWaterPagedPoolUsage;
        public uint HighWaterNonPagedPoolUsage;
        public uint HighWaterNamePoolUsage;
        public uint HighWaterHandleTableUsage;
        public AttributeFlags InvalidAttributes;
        public GenericMapping GenericMapping;
        public uint ValidAccess;
        public byte SecurityRequired;
        public byte MaintainHandleCount;
        public ushort MaintainTypeList;
        public PoolType PoolType;
        public uint PagedPoolUsage;
        public uint NonPagedPoolUsage;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ObjectAllTypesInformation
    {
        public int NumberOfTypes;
        //ObjectTypeInformation TypeInformation; // Type Info list
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtClose(IntPtr handle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtDuplicateObject(
          SafeHandle SourceProcessHandle,
          IntPtr SourceHandle,
          SafeHandle TargetProcessHandle,
          out IntPtr TargetHandle,
          AccessMask DesiredAccess,
          AttributeFlags HandleAttributes,
          DuplicateObjectOptions Options
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtDuplicateObject(
          SafeHandle SourceProcessHandle,
          IntPtr SourceHandle,
          IntPtr TargetProcessHandle,
          IntPtr TargetHandle,
          AccessMask DesiredAccess,
          AttributeFlags HandleAttributes,
          DuplicateObjectOptions Options
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryObject(
            SafeHandle ObjectHandle,
            ObjectInformationClass ObjectInformationClass,
            SafeBuffer ObjectInformation,
            int ObjectInformationLength,
            out int ReturnLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetInformationObject(
            SafeHandle ObjectHandle,
            ObjectInformationClass ObjectInformationClass,
            SafeBuffer ObjectInformation,
            int ObjectInformationLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtMakeTemporaryObject(SafeKernelObjectHandle Handle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtMakePermanentObject(SafeKernelObjectHandle Handle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCompareObjects(SafeKernelObjectHandle Object1, SafeKernelObjectHandle Object2);
    }
#pragma warning restore 1591

}
