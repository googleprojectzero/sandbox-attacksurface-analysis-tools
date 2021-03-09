﻿//  Copyright 2019 Google Inc. All Rights Reserved.
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
    [Flags]
    public enum LoadKeyFlags
    {
        None = 0,
        AppKey = 0x10,
        Exclusive = 0x20,
        DisableResourceManager = 0x100,
        Unknown800 = 0x800,
        ReadOnly = 0x2000,
        DontCheckAccess = 0x8000,
    }

    [Flags]
    public enum KeyAccessRights : uint
    {
        [SDKName("KEY_QUERY_VALUE")]
        QueryValue = 0x0001,
        [SDKName("KEY_SET_VALUE")]
        SetValue = 0x0002,
        [SDKName("KEY_CREATE_SUB_KEY")]
        CreateSubKey = 0x0004,
        [SDKName("KEY_ENUMERATE_SUB_KEYS")]
        EnumerateSubKeys = 0x0008,
        [SDKName("KEY_NOTIFY")]
        Notify = 0x0010,
        [SDKName("KEY_CREATE_LINK")]
        CreateLink = 0x0020,
        [SDKName("GENERIC_READ")]
        GenericRead = GenericAccessRights.GenericRead,
        [SDKName("GENERIC_WRITE")]
        GenericWrite = GenericAccessRights.GenericWrite,
        [SDKName("GENERIC_EXECUTE")]
        GenericExecute = GenericAccessRights.GenericExecute,
        [SDKName("GENERIC_ALL")]
        GenericAll = GenericAccessRights.GenericAll,
        [SDKName("DELETE")]
        Delete = GenericAccessRights.Delete,
        [SDKName("READ_CONTROL")]
        ReadControl = GenericAccessRights.ReadControl,
        [SDKName("WRITE_DAC")]
        WriteDac = GenericAccessRights.WriteDac,
        [SDKName("WRITE_OWNER")]
        WriteOwner = GenericAccessRights.WriteOwner,
        [SDKName("SYNCHRONIZE")]
        Synchronize = GenericAccessRights.Synchronize,
        [SDKName("MAXIMUM_ALLOWED")]
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
        [SDKName("ACCESS_SYSTEM_SECURITY")]
        AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
    }

    public enum RegistryValueType
    {
        None = 0,
        String = 1,
        ExpandString = 2,
        Binary = 3,
        Dword = 4,
        DwordBigEndian = 5,
        Link = 6,
        MultiString = 7,
        ResourceList = 8,
        FullResourceDescriptor = 9,
        ResourceRequirementsList = 10,
        Qword = 11
    }

    public enum KeyDisposition
    {
        CreatedNewKey = 1,
        OpenedExistingKey = 2,
    }

    [Flags]
    public enum KeyCreateOptions
    {
        NonVolatile = 0,
        Volatile = 1,
        CreateLink = 2,
        BackupRestore = 4,
        OpenLink = 8,
    }

    public enum KeyValueInformationClass
    {
        KeyValueBasicInformation = 0,
        KeyValueFullInformation,
        KeyValuePartialInformation,
        KeyValueFullInformationAlign64,
        KeyValuePartialInformationAlign64,
        KeyValueLayerInformation,
        MaxKeyValueInfoClass
    }

    [StructLayout(LayoutKind.Sequential)]
    [DataStart("Data")]
    public class KeyValuePartialInformation
    {
        public int TitleIndex;
        public RegistryValueType Type;
        public int DataLength;
        public byte Data; // Trailing data
    }

    [StructLayout(LayoutKind.Sequential)]
    [DataStart("Name")]
    public class KeyValueFullInformation
    {
        public int TitleIndex;
        public RegistryValueType Type;
        public int DataOffset;
        public int DataLength;
        public int NameLength;
        public ushort Name;
    }

    public enum KeyInformationClass
    {
        KeyBasicInformation = 0,
        KeyNodeInformation = 1,
        KeyFullInformation = 2,
        KeyNameInformation = 3,
        KeyCachedInformation = 4,
        KeyFlagsInformation = 5,
        KeyVirtualizationInformation = 6,
        KeyHandleTagsInformation = 7,
        KeyTrustInformation = 8,
        KeyLayerInformation = 9,
    }

    public enum KeySetInformationClass
    {
        KeyWriteTimeInformation,
        KeyWow64FlagsInformation,
        KeyControlFlagsInformation,
        KeySetVirtualizationInformation,
        KeySetDebugInformation,
        KeySetHandleTagsInformation,
        KeySetLayerInformation
    }

    [StructLayout(LayoutKind.Sequential)]
    [DataStart("Name")]
    public class KeyBasicInformation
    {
        public LargeIntegerStruct LastWriteTime;
        public int TitleIndex;
        public int NameLength;
        public ushort Name;
    }

    [StructLayout(LayoutKind.Sequential)]
    [DataStart("Name")]
    public class KeyNodeInformation
    {
        public LargeIntegerStruct LastWriteTime;
        public int TitleIndex;
        public int ClassOffset;
        public int ClassLength;
        public int NameLength;
        public ushort Name; // Variable length string
        // Class[1]; // Variable length string not declared
    }

    [StructLayout(LayoutKind.Sequential)]
    [DataStart("Name")]
    public class KeyNameInformation
    {
        public int NameLength;
        public ushort Name; // Trailing name
    }

    [StructLayout(LayoutKind.Sequential)]
    [DataStart("Class")]
    public class KeyFullInformation
    {
        public LargeIntegerStruct LastWriteTime;
        public int TitleIndex;
        public int ClassOffset;
        public int ClassLength;
        public int SubKeys;
        public int MaxNameLen;
        public int MaxClassLen;
        public int Values;
        public int MaxValueNameLen;
        public int MaxValueDataLen;
        public ushort Class; // Variable length string
    }

    [Flags]
    public enum SaveKeyFlags
    {
        None = 0,
        StandardFormat = 1,
        LatestFormat = 2,
        NoCompression = 4,
    }

    [Flags]
    public enum RestoreKeyFlags
    {
        None = 0,
        WholeHiveVolatile = 1,
        RefreshHive = 2,
        ForceRestore = 8,
    }

    [Flags]
    public enum NotifyCompletionFilter
    {
        None = 0,
        Name = 1,
        Attributes = 2,
        LastSet = 4,
        Security = 8,
        All = Name | Attributes | LastSet | Security,
        ThreadAgnostic = 0x10000000
    }

    [Flags]
    public enum KeyVirtualizationFlags
    {
        None = 0,
        VirtualizationCandidate = 1,
        VirtualizationEnabled = 2,
        VirtualTarget = 4,
        VirtualStore = 8,
        VirtualSource = 0x10,
    }

    [Flags]
    public enum KeySetVirtualizationFlags
    {
        None = 0,
        VirtualTarget = 1,
        VirtualStore = 2,
        VirtualSource = 4,
    }

    [Flags]
    public enum KeyControlFlags
    {
        None = 0,
        DontVirtualize = 2,
        DontSilentFail = 4,
        RecurseFlag = 8
    }

    [Flags]
    public enum UnloadKeyFlags
    {
        None = 0,
        ForceUnload = 1
    }

    [Flags]
    public enum KeyFlags
    {
        None = 0,
        Volatile = 1,
        Link = 2,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KeyFlagsInformation
    {
        public int Wow64Flags;
        public KeyFlags KeyFlags;
        public KeyControlFlags ControlFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KeyTrustInformation
    {
        public int Flags;
        public bool TrustedKey => Flags.GetBit(0);
    }

    public enum KeyLoadArgumentType : byte
    {
        TrustKeyHandle = 1,
        EventHandle,
        TokenHandle
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KeyLoadArgument
    {
        public KeyLoadArgumentType ArgumentType;
        public IntPtr Argument;
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateKey(
            out SafeKernelObjectHandle KeyHandle,
            KeyAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes,
            int TitleIndex,
            UnicodeString Class,
            KeyCreateOptions CreateOptions,
            out KeyDisposition Disposition
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenKey(
            out SafeKernelObjectHandle KeyHandle,
            KeyAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenKeyEx(
            out SafeKernelObjectHandle KeyHandle,
            KeyAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes,
            KeyCreateOptions OpenOptions
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtDeleteKey(SafeKernelObjectHandle KeyHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetValueKey(
          SafeKernelObjectHandle KeyHandle,
          UnicodeString ValueName,
          int TitleIndex,
          RegistryValueType Type,
          byte[] Data,
          int DataSize);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryValueKey(
            SafeKernelObjectHandle KeyHandle,
            UnicodeString ValueName,
            KeyValueInformationClass KeyValueInformationClass,
            SafeBuffer KeyValueInformation,
            int Length,
            out int ResultLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenKeyTransacted(out SafeKernelObjectHandle KeyHandle, KeyAccessRights DesiredAccess, [In] ObjectAttributes ObjectAttributes, [In] SafeKernelObjectHandle TransactionHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenKeyTransactedEx(out SafeKernelObjectHandle KeyHandle, KeyAccessRights DesiredAccess, [In] ObjectAttributes ObjectAttributes, KeyCreateOptions OpenOptions, [In] SafeKernelObjectHandle TransactionHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateKeyTransacted(
            out SafeKernelObjectHandle KeyHandle,
            KeyAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes,
            int TitleIndex,
            UnicodeString Class,
            KeyCreateOptions CreateOptions,
            SafeKernelObjectHandle TransactionHandle,
            out KeyDisposition Disposition
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtLoadKeyEx([In] ObjectAttributes DestinationName, [In] ObjectAttributes FileName, LoadKeyFlags Flags,
          IntPtr TrustKeyHandle, IntPtr EventHandle, KeyAccessRights DesiredAccess, out SafeKernelObjectHandle KeyHandle, int Unused);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtLoadKeyEx([In] ObjectAttributes DestinationName, [In] ObjectAttributes FileName, LoadKeyFlags Flags,
            IntPtr TrustKeyHandle, IntPtr EventHandle, KeyAccessRights DesiredAccess, IntPtr KeyHandle, int Unused);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtLoadKey3([In] ObjectAttributes DestinationName, [In] ObjectAttributes FileName, LoadKeyFlags Flags,
            [In, MarshalAs(UnmanagedType.LPArray)] KeyLoadArgument[] LoadArguments, int LoadArgumentCount, KeyAccessRights DesiredAccess, out SafeKernelObjectHandle KeyHandle, int Unused);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtLoadKey3([In] ObjectAttributes DestinationName, [In] ObjectAttributes FileName, LoadKeyFlags Flags,
            [In, MarshalAs(UnmanagedType.LPArray)] KeyLoadArgument[] LoadArguments, int LoadArgumentCount, KeyAccessRights DesiredAccess, IntPtr KeyHandle, int Unused);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtUnloadKey2([In] ObjectAttributes KeyObjectAttributes, UnloadKeyFlags Flags);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtEnumerateKey(
              SafeKernelObjectHandle KeyHandle,
              int Index,
              KeyInformationClass KeyInformationClass,
              SafeBuffer KeyInformation,
              int Length,
              out int ResultLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtEnumerateValueKey(
          SafeKernelObjectHandle KeyHandle,
          int Index,
          KeyValueInformationClass KeyValueInformationClass,
          SafeBuffer KeyValueInformation,
          int Length,
          out int ResultLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtDeleteValueKey(
                SafeKernelObjectHandle KeyHandle,
                UnicodeString ValueName
            );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryKey(
                SafeKernelObjectHandle KeyHandle,
                KeyInformationClass KeyInformationClass,
                SafeBuffer KeyInformation,
                int Length,
                out int ResultLength
            );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRenameKey(
                SafeKernelObjectHandle KeyHandle,
                [In] UnicodeString NewName
            );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSaveKeyEx(
                SafeKernelObjectHandle KeyHandle,
                SafeKernelObjectHandle FileHandle,
                SaveKeyFlags Flags
            );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRestoreKey(
                SafeKernelObjectHandle KeyHandle,
                SafeKernelObjectHandle FileHandle,
                RestoreKeyFlags Flags
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryLicenseValue(
            [In] UnicodeString Name,
            out RegistryValueType Type,
            SafeBuffer Buffer,
            int Length,
            out int DataLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtLockRegistryKey(
                SafeKernelObjectHandle KeyHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtLockProductActivationKeys(
            OptionalInt32 pPrivateVer, OptionalInt32 pSafeMode);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtNotifyChangeKey(
              SafeKernelObjectHandle KeyHandle,
              SafeKernelObjectHandle Event,
              IntPtr ApcRoutine,
              IntPtr ApcContext,
              SafeIoStatusBuffer IoStatusBlock,
              NotifyCompletionFilter CompletionFilter,
              bool WatchTree,
              SafeBuffer Buffer,
              int BufferSize,
              bool Asynchronous
            );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtNotifyChangeMultipleKeys(
          SafeKernelObjectHandle MasterKeyHandle,
          int Count,    // Can only be 1.
          ObjectAttributes SubordinateObjects,
          SafeKernelObjectHandle Event,
          IntPtr ApcRoutine,
          IntPtr ApcContext,
          SafeIoStatusBuffer IoStatusBlock,
          NotifyCompletionFilter CompletionFilter,
          bool WatchTree,
          SafeBuffer Buffer,
          int BufferSize,
          bool Asynchronous);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetInformationKey(
             SafeKernelObjectHandle KeyHandle,
             KeySetInformationClass KeySetInformationClass,
             SafeBuffer KeySetInformation,
             int KeySetInformationLength);
    }
#pragma warning restore 1591
}
