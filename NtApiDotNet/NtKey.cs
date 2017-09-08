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

using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace NtApiDotNet
{
#pragma warning disable 1591
    [Flags]
    public enum LoadKeyFlags
    {
        None = 0,
        AppKey = 0x10,
        Exclusive = 0x20,
        Unknown800 = 0x800,
        ReadOnly = 0x2000,
    }

    [Flags]
    public enum KeyAccessRights : uint
    {
        QueryValue = 0x0001,
        SetValue = 0x0002,
        CreateSubKey = 0x0004,
        EnumerateSubKeys = 0x0008,
        Notify = 0x0010,
        CreateLink = 0x0020,
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
        public static extern NtStatus NtOpenKeyTransactedEx(out SafeKernelObjectHandle KeyHandle, KeyAccessRights DesiredAccess, [In] ObjectAttributes ObjectAttributes, int OpenOptions, [In] SafeKernelObjectHandle TransactionHandle);

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

    }
#pragma warning restore 1591

    /// <summary>
    /// Class representing a single Key value
    /// </summary>
    public class NtKeyValue
    {
        /// <summary>
        /// Name of the value
        /// </summary>
        public string Name { get; private set; }
        /// <summary>
        /// Type of the value
        /// </summary>
        public RegistryValueType Type { get; private set; }
        /// <summary>
        /// Raw data for the value
        /// </summary>
        public byte[] Data { get; private set; }
        /// <summary>
        /// Title index for the value
        /// </summary>
        public int TitleIndex { get; private set; }

        internal NtKeyValue(string name, RegistryValueType type, byte[] data, int title_index)
        {
            Name = name;
            Type = type;
            Data = data;
            TitleIndex = title_index;
        }

        /// <summary>
        /// Convert the value to a string
        /// </summary>
        /// <returns>The value as a string</returns>
        public override string ToString()
        {
            switch (Type)
            {
                case RegistryValueType.String:
                case RegistryValueType.ExpandString:
                case RegistryValueType.Link:
                case RegistryValueType.MultiString:
                    return Encoding.Unicode.GetString(Data);
                case RegistryValueType.Dword:
                    return BitConverter.ToUInt32(Data, 0).ToString();
                case RegistryValueType.DwordBigEndian:
                    return BitConverter.ToUInt32(Data.Reverse().ToArray(), 0).ToString();
                case RegistryValueType.Qword:
                    return BitConverter.ToUInt64(Data, 0).ToString();
                default:
                    return Convert.ToBase64String(Data);
            }
        }

        /// <summary>
        /// Convert value to an object
        /// </summary>
        /// <returns>The value as an object</returns>
        public object ToObject()
        {
            switch (Type)
            {
                case RegistryValueType.String:
                case RegistryValueType.ExpandString:
                case RegistryValueType.Link:
                    return Encoding.Unicode.GetString(Data);
                case RegistryValueType.MultiString:
                    return Encoding.Unicode.GetString(Data).Split(new char[] { '\0' }, StringSplitOptions.RemoveEmptyEntries);
                case RegistryValueType.Dword:
                    return BitConverter.ToUInt32(Data, 0);
                case RegistryValueType.DwordBigEndian:
                    return BitConverter.ToUInt32(Data.Reverse().ToArray(), 0);
                case RegistryValueType.Qword:
                    return BitConverter.ToUInt64(Data, 0);
                default:
                    return Data;
            }
        }
    }

    /// <summary>
    /// Class to represent an NT Key object
    /// </summary>
    [NtType("Key")]
    public class NtKey : NtObjectWithDuplicate<NtKey, KeyAccessRights>
    {
        internal NtKey(SafeKernelObjectHandle handle, KeyDisposition disposition) : base(handle)
        {
            Disposition = disposition;
        }

        /// <summary>
        /// Load a new hive
        /// </summary>
        /// <param name="destination">The destination path</param>
        /// <param name="filename">The path to the hive</param>
        /// <param name="flags">Load flags</param>
        /// <returns>The opened root key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey LoadKey(string destination, string filename, LoadKeyFlags flags)
        {
            using (ObjectAttributes dest = new ObjectAttributes(destination, AttributeFlags.CaseInsensitive))
            {
                using (ObjectAttributes name = new ObjectAttributes(filename, AttributeFlags.CaseInsensitive))
                {
                    return LoadKey(dest, name, flags, KeyAccessRights.MaximumAllowed);
                }
            }
        }

        /// <summary>
        /// Load a new hive
        /// </summary>
        /// <param name="key_obj_attr">Object attributes for the key name</param>
        /// <param name="file_obj_attr">Object attributes for the path to the hive file</param>
        /// <param name="flags">Load flags</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <returns>The opened root key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey LoadKey(ObjectAttributes key_obj_attr, ObjectAttributes file_obj_attr, LoadKeyFlags flags, KeyAccessRights desired_access)
        {
            return LoadKey(key_obj_attr, file_obj_attr, flags, desired_access, true).Result;
        }

        /// <summary>
        /// Load a new hive
        /// </summary>
        /// <param name="key_obj_attr">Object attributes for the key name</param>
        /// <param name="file_obj_attr">Object attributes for the path to the hive file</param>
        /// <param name="flags">Load flags</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtKey> LoadKey(ObjectAttributes key_obj_attr, ObjectAttributes file_obj_attr, 
            LoadKeyFlags flags, KeyAccessRights desired_access, bool throw_on_error)
        {
            SafeKernelObjectHandle key_handle;
            return NtSystemCalls.NtLoadKeyEx(key_obj_attr, file_obj_attr, flags,
                IntPtr.Zero, IntPtr.Zero, desired_access, out key_handle, 0)
                .CreateResult(throw_on_error, () => new NtKey(key_handle, KeyDisposition.OpenedExistingKey));
        }

        /// <summary>
        /// Create a new Key
        /// </summary>
        /// <param name="obj_attributes">Object attributes for the key name</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <param name="options">Create options</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtKey> Create(ObjectAttributes obj_attributes, KeyAccessRights desired_access, KeyCreateOptions options, bool throw_on_error)
        {
            SafeKernelObjectHandle handle;
            KeyDisposition disposition;
            return NtSystemCalls.NtCreateKey(out handle, desired_access, obj_attributes, 0, null, options, out disposition)
                .CreateResult(throw_on_error, () => new NtKey(handle, disposition));
        }

        /// <summary>
        /// Create a new Key
        /// </summary>
        /// <param name="obj_attributes">Object attributes for the key name</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <param name="options">Create options</param>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey Create(ObjectAttributes obj_attributes, KeyAccessRights desired_access, KeyCreateOptions options)
        {
            return Create(obj_attributes, desired_access, options, true).Result;
        }

        /// <summary>
        /// Create a new Key
        /// </summary>
        /// <param name="key_name">Path to the key to create</param>
        /// <param name="root">Root key if key_name is relative</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <param name="options">Create options</param>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey Create(string key_name, NtObject root, KeyAccessRights desired_access, KeyCreateOptions options)
        {
            using (ObjectAttributes obja = new ObjectAttributes(key_name, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, desired_access, options);
            }
        }

        /// <summary>
        /// Create a new Key
        /// </summary>
        /// <param name="key_name">Path to the key to create</param>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtKey Create(string key_name)
        {
            return Create(key_name, this, KeyAccessRights.MaximumAllowed, KeyCreateOptions.NonVolatile);
        }

        /// <summary>
        /// Create a new Key
        /// </summary>
        /// <param name="key_name">Path to the key to create</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <param name="options">Create options</param>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtKey Create(string key_name, KeyAccessRights desired_access, KeyCreateOptions options)
        {
            return Create(key_name, this, desired_access, options);
        }

        /// <summary>
        /// Try and open a Key
        /// </summary>
        /// <param name="obj_attributes">Object attributes for the key name</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <param name="open_options">Open options.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtKey> Open(ObjectAttributes obj_attributes, KeyAccessRights desired_access, KeyCreateOptions open_options, bool throw_on_error)
        {
            SafeKernelObjectHandle handle;
            return NtSystemCalls.NtOpenKeyEx(out handle, desired_access, obj_attributes, open_options)
                .CreateResult(throw_on_error, () => new NtKey(handle, KeyDisposition.OpenedExistingKey));
        }

        internal static NtResult<NtObject> FromName(ObjectAttributes object_attributes, AccessMask desired_access, bool throw_on_error)
        {
            return Open(object_attributes, desired_access.ToSpecificAccess<KeyAccessRights>(), 0, throw_on_error).Cast<NtObject>();
        }

        /// <summary>
        /// Open a Key
        /// </summary>
        /// <param name="obj_attributes">Object attributes for the key name</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <param name="open_options">Open options.</param>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey Open(ObjectAttributes obj_attributes, KeyAccessRights desired_access, KeyCreateOptions open_options)
        {
            return Open(obj_attributes, desired_access, open_options, true).Result;
        }

        /// <summary>
        /// Open a Key
        /// </summary>
        /// <param name="key_name">Path to the key to open</param>
        /// <param name="root">Root key if key_name is relative</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey Open(string key_name, NtObject root, KeyAccessRights desired_access)
        {
            using (ObjectAttributes obja = new ObjectAttributes(key_name, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obja, desired_access, 0);
            }
        }

        /// <summary>
        /// Delete the key
        /// </summary>
        public void Delete()
        {
            NtSystemCalls.NtDeleteKey(Handle).ToNtException();
        }

        /// <summary>
        /// Set a resistry value
        /// </summary>
        /// <param name="value_name">The name of the value</param>
        /// <param name="type">The type of the value</param>
        /// <param name="data">The raw value data</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void SetValue(string value_name, RegistryValueType type, byte[] data)
        {
            NtSystemCalls.NtSetValueKey(Handle, new UnicodeString(value_name ?? String.Empty), 
                0, type, data, data.Length).ToNtException();
        }

        /// <summary>
        /// Set a string resistry value
        /// </summary>
        /// <param name="value_name">The name of the value</param>
        /// <param name="type">The type of the value</param>
        /// <param name="data">The value data</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void SetValue(string value_name, RegistryValueType type, string data)
        {
            SetValue(value_name, type, Encoding.Unicode.GetBytes(data));
        }

        /// <summary>
        /// Set a DWORD resistry value
        /// </summary>
        /// <param name="value_name">The name of the value</param>
        /// <param name="data">The value data</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void SetValue(string value_name, uint data)
        {
            SetValue(value_name, RegistryValueType.Dword, BitConverter.GetBytes(data));
        }

        /// <summary>
        /// Set a QWORD resistry value
        /// </summary>
        /// <param name="value_name">The name of the value</param>
        /// <param name="data">The value data</param>
        /// <exception cref="NtException">Thrown on error.</exception>
        public void SetValue(string value_name, ulong data)
        {
            SetValue(value_name, RegistryValueType.Qword, BitConverter.GetBytes(data));
        }

        /// <summary>
        /// Query a value by name
        /// </summary>
        /// <param name="value_name">The name of the value</param>
        /// <param name="throw_on_error">True to throw on error</param>
        /// <returns>The value information</returns>
        public NtResult<NtKeyValue> QueryValue(string value_name, bool throw_on_error)
        {
            UnicodeString name = new UnicodeString(value_name);
            int return_len = 0;
            int query_count = 0;

            while (query_count++ < 64)
            {
                using (var info = new SafeStructureInOutBuffer<KeyValuePartialInformation>(return_len, false))
                {
                    NtStatus status = NtSystemCalls.NtQueryValueKey(Handle, name, KeyValueInformationClass.KeyValuePartialInformation,
                        info, info.Length, out return_len);
                    if (status == NtStatus.STATUS_BUFFER_OVERFLOW || status == NtStatus.STATUS_BUFFER_TOO_SMALL)
                    {
                        continue;
                    }

                    return status.CreateResult(throw_on_error, () =>
                    {
                        KeyValuePartialInformation result = info.Result;
                        return new NtKeyValue(value_name, info.Result.Type,
                                    info.Data.ReadBytes(result.DataLength), result.TitleIndex);
                    });
                }
            }
            return NtStatus.STATUS_BUFFER_TOO_SMALL.CreateResultFromError<NtKeyValue>(throw_on_error);
        }

        /// <summary>
        /// Query a value by name
        /// </summary>
        /// <param name="value_name">The name of the value</param>
        /// <returns>The value information</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtKeyValue QueryValue(string value_name)
        {
            return QueryValue(value_name, true).Result;
        }

        /// <summary>
        /// Query all values for this key
        /// </summary>
        /// <returns>A list of values</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public IEnumerable<NtKeyValue> QueryValues()
        {
            int index = 0;
            using (SafeStructureInOutBuffer<KeyValueFullInformation> value_info = new SafeStructureInOutBuffer<KeyValueFullInformation>(512, true))
            {
                while (true)
                {
                    int result_length;
                    NtStatus status = NtSystemCalls.NtEnumerateValueKey(Handle, index, KeyValueInformationClass.KeyValueFullInformation,
                        value_info, value_info.Length, out result_length);
                    if (status == NtStatus.STATUS_BUFFER_OVERFLOW || status == NtStatus.STATUS_BUFFER_TOO_SMALL)
                    {
                        value_info.Resize(result_length);
                        continue;
                    }
                    index++;
                    if (status != NtStatus.STATUS_SUCCESS)
                    {
                        break;
                    }
                    KeyValueFullInformation res = value_info.Result;
                    char[] name_buffer = new char[res.NameLength / 2];
                    value_info.Data.ReadArray(0, name_buffer, 0, name_buffer.Length);
                    string name = new string(name_buffer);
                    byte[] data_buffer = new byte[res.DataLength];
                    value_info.ReadArray((ulong)res.DataOffset, data_buffer, 0, data_buffer.Length);
                    yield return new NtKeyValue(name, res.Type, data_buffer, res.TitleIndex);
                }
            }
        }

        /// <summary>
        /// Query a license value. While technically not directly a registry key
        /// it has many of the same properties such as using the same registry
        /// value types.
        /// </summary>
        /// <param name="name">The name of the license value.</param>
        /// <param name="throw_on_error">True to throw an exception on error</param>
        /// <returns>The license value key</returns>
        public static NtResult<NtKeyValue> QueryLicenseValue(string name, bool throw_on_error)
        {
            RegistryValueType type;
            int ret_length;
            UnicodeString name_string = new UnicodeString(name);
            NtStatus status = NtSystemCalls.NtQueryLicenseValue(name_string, out type, SafeHGlobalBuffer.Null, 0, out ret_length);
            if (status != NtStatus.STATUS_BUFFER_TOO_SMALL)
            {
                return status.CreateResultFromError<NtKeyValue>(throw_on_error);
            }

            using (var buffer = new SafeHGlobalBuffer(ret_length))
            {
                return NtSystemCalls.NtQueryLicenseValue(name_string, out type, buffer, buffer.Length, out ret_length)
                    .CreateResult(throw_on_error, () => new NtKeyValue(name, type, buffer.ToArray(), 0));
            }
        }

        /// <summary>
        /// Query a license value. While technically not directly a registry key
        /// it has many of the same properties such as using the same registry
        /// value types.
        /// </summary>
        /// <param name="name">The name of the license value.</param>
        /// <returns>The license value key</returns>
        public static NtKeyValue QueryLicenseValue(string name)
        {
            return QueryLicenseValue(name, true).Result;
        }

        /// <summary>
        /// Query all subkey names
        /// </summary>
        /// <returns>The list of subkey names</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public IEnumerable<string> QueryKeys()
        {
            int index = 0;
            using (SafeStructureInOutBuffer<KeyBasicInformation> name_info = new SafeStructureInOutBuffer<KeyBasicInformation>(512, true))
            {
                while (true)
                {
                    int result_length;
                    NtStatus status = NtSystemCalls.NtEnumerateKey(Handle, index, KeyInformationClass.KeyBasicInformation, name_info, name_info.Length, out result_length);
                    if (status == NtStatus.STATUS_BUFFER_OVERFLOW || status == NtStatus.STATUS_BUFFER_TOO_SMALL)
                    {
                        name_info.Resize(result_length);
                        continue;
                    }
                    index++;
                    if (status != NtStatus.STATUS_SUCCESS)
                    {
                        break;
                    }
                    KeyBasicInformation res = name_info.Result;
                    char[] name_buffer = new char[res.NameLength / 2];
                    name_info.Data.ReadArray(0, name_buffer, 0, name_buffer.Length);
                    yield return new string(name_buffer);
                }
            }
        }

        /// <summary>
        /// Return a list of subkeys which can be accessed.
        /// </summary>
        /// <param name="desired_access">The required access rights for the subkeys</param>
        /// <param name="open_link">True to open link keys rather than following the link.</param>
        /// <param name="open_for_backup">True to open keys with backup flag set.</param>
        /// <returns>The disposable list of subkeys.</returns>
        public IEnumerable<NtKey> QueryAccessibleKeys(KeyAccessRights desired_access, bool open_link, bool open_for_backup)
        {
            List<NtKey> ret = new List<NtKey>();
            AttributeFlags flags = AttributeFlags.CaseInsensitive;
            if (open_link)
            {
                flags |= AttributeFlags.OpenLink;
            }

            if (IsAccessGranted(KeyAccessRights.EnumerateSubKeys))
            {
                foreach (string name in QueryKeys())
                {
                    using (ObjectAttributes obja = new ObjectAttributes(name, flags, this))
                    {
                        var result = Open(obja, desired_access, open_for_backup ? KeyCreateOptions.BackupRestore : 0, false);
                        if (result.IsSuccess)
                        {
                            ret.Add(result.Result);
                        }
                    }
                }
            }
            return ret;
        }

        /// <summary>
        /// Return a list of subkeys which can be accessed.
        /// </summary>
        /// <param name="desired_access">The required access rights for the subkeys</param>
        /// <returns>The disposable list of subkeys.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public IEnumerable<NtKey> QueryAccessibleKeys(KeyAccessRights desired_access)
        {
            return QueryAccessibleKeys(desired_access, false, false);
        }

        /// <summary>
        /// Set a symbolic link target for this key (must have been created with
        /// appropriate create flags)
        /// </summary>
        /// <param name="target">The symbolic link target.</param>
        public void SetSymbolicLinkTarget(string target)
        {
            SetValue("SymbolicLinkValue", RegistryValueType.Link, Encoding.Unicode.GetBytes(target));
        }

        /// <summary>
        /// Create a registry key symbolic link
        /// </summary>
        /// <param name="rootkey">Root key if path is relative</param>
        /// <param name="path">Path to the key to create</param>
        /// <param name="target">Target resistry path</param>
        /// <returns>The created symbolic link key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey CreateSymbolicLink(string path, NtKey rootkey, string target)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, 
                AttributeFlags.CaseInsensitive | AttributeFlags.OpenIf | AttributeFlags.OpenLink, rootkey))
            {
                using (NtKey key = Create(obja, KeyAccessRights.MaximumAllowed, KeyCreateOptions.CreateLink))
                {
                    try
                    {
                        key.SetSymbolicLinkTarget(target);
                        return key.Duplicate();
                    }
                    catch
                    {
                        key.Delete();
                        throw;
                    }
                }
            }
        }

        /// <summary>
        /// Open a key
        /// </summary>
        /// <param name="key_name">The path to the key to open</param>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtKey Open(string key_name)
        {
            return Open(key_name, this, KeyAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Open a key
        /// </summary>
        /// <param name="key_name">The path to the key to open</param>
        /// <param name="desired_access">Access rights for the key</param>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtKey Open(string key_name, KeyAccessRights desired_access)
        {
            return Open(key_name, this, desired_access);
        }

        /// <summary>
        /// Open the machine key
        /// </summary>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey GetMachineKey()
        {
            return Open(@"\Registry\Machine", null, KeyAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Open the user key
        /// </summary>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey GetUserKey()
        {
            return Open(@"\Registry\User", null, KeyAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Open a specific user key
        /// </summary>
        /// <param name="sid">The SID fo the user to open</param>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey GetUserKey(Sid sid)
        {
            return Open(@"\Registry\User\" + sid.ToString(), null, KeyAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Open the current user key
        /// </summary>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey GetCurrentUserKey()
        {
            return GetUserKey(NtToken.CurrentUser.Sid);
        }

        /// <summary>
        /// Open the root key
        /// </summary>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey GetRootKey()
        {
            return Open(@"\Registry", null, KeyAccessRights.MaximumAllowed);
        }

        private static SafeRegistryHandle DuplicateAsRegistry(SafeKernelObjectHandle handle)
        {
            using (var dup_handle = DuplicateHandle(handle))
            {
                SafeRegistryHandle ret = new SafeRegistryHandle(dup_handle.DangerousGetHandle(), true);
                dup_handle.SetHandleAsInvalid();
                return ret;
            }
        }

        /// <summary>
        /// Convert object to a .NET RegistryKey object
        /// </summary>
        /// <returns>The registry key object</returns>
        public RegistryKey ToRegistryKey()
        {
            return RegistryKey.FromHandle(DuplicateAsRegistry(Handle));
        }

        /// <summary>
        /// Rename key.
        /// </summary>
        /// <param name="new_name">The new name for the key.</param>
        public void Rename(string new_name)
        {
            NtSystemCalls.NtRenameKey(Handle, new UnicodeString(new_name)).ToNtException();
        }

        /// <summary>
        /// Save the opened key into a file.
        /// </summary>
        /// <param name="file">The file to save to.</param>
        /// <param name="flags">Save key flags</param>
        public void Save(NtFile file, SaveKeyFlags flags)
        {
            NtSystemCalls.NtSaveKeyEx(Handle, file.Handle,
                flags).ToNtException();
        }

        /// <summary>
        /// Save the opened key into a file.
        /// </summary>
        /// <param name="path">The file path to save to.</param>
        /// <param name="flags">Save key flags</param>
        public void Save(string path, SaveKeyFlags flags)
        {
            using (NtFile file = NtFile.Create(path, null, FileAccessRights.GenericWrite | FileAccessRights.Synchronize,
                FileAttributes.Normal, FileShareMode.None, FileOpenOptions.SynchronousIoNonAlert, FileDisposition.Create, null))
            {
                Save(file, flags);
            }
        }

        /// <summary>
        /// Save the opened key into a file.
        /// </summary>
        /// <param name="path">The file path to save to.</param>
        public void Save(string path)
        {
            Save(path, SaveKeyFlags.StandardFormat);
        }

        /// <summary>
        /// Restore key from a file.
        /// </summary>
        /// <param name="file">The file to restore from</param>
        /// <param name="flags">Restore key flags</param>
        public void Restore(NtFile file, RestoreKeyFlags flags)
        {
            NtSystemCalls.NtRestoreKey(Handle, file.Handle, flags).ToNtException();
        }

        /// <summary>
        /// Restore key from a file.
        /// </summary>
        /// <param name="path">The file path to restore from</param>
        /// <param name="flags">Restore key flags</param>
        public void Restore(string path, RestoreKeyFlags flags)
        {
            using (NtFile file = NtFile.Open(path, null, FileAccessRights.GenericRead | FileAccessRights.Synchronize,
                    FileShareMode.Read, FileOpenOptions.SynchronousIoNonAlert))
            {
                Restore(file, flags);
            }
        }

        /// <summary>
        /// Restore key from a file.
        /// </summary>
        /// <param name="path">The file path to restore from</param>
        public void Restore(string path)
        {
            Restore(path, RestoreKeyFlags.None);
        }

        /// <summary>
        /// Try and lock the registry key to prevent further modification.
        /// </summary>
        /// <remarks>Note that this almost certainly never works from usermode, there's an explicit
        /// check to prevent it in the kernel.</remarks>
        public void Lock()
        {
            NtSystemCalls.NtLockRegistryKey(Handle).ToNtException();
        }

        private SafeStructureInOutBuffer<T> QueryKey<T>(KeyInformationClass info_class) where T : new()
        {
            int return_length;
            NtStatus status = NtSystemCalls.NtQueryKey(Handle, info_class, SafeHGlobalBuffer.Null, 0, out return_length);
            if (status != NtStatus.STATUS_BUFFER_OVERFLOW && status != NtStatus.STATUS_INFO_LENGTH_MISMATCH && status != NtStatus.STATUS_BUFFER_TOO_SMALL)
            {
                status.ToNtException();
            }
            SafeStructureInOutBuffer<T> buffer = new SafeStructureInOutBuffer<T>(return_length, false);
            try
            {
                NtSystemCalls.NtQueryKey(Handle, info_class, buffer, buffer.Length, out return_length).ToNtException();
                return Interlocked.Exchange(ref buffer, null);
            }
            finally
            {
                if (buffer != null)
                {
                    buffer.Close();
                }
            }
        }

        private Tuple<KeyFullInformation, string> GetFullInfo()
        {
            using (var buffer = QueryKey<KeyFullInformation>(KeyInformationClass.KeyFullInformation))
            {
                KeyFullInformation ret = buffer.Result;
                byte[] class_name = new byte[ret.ClassLength];
                if ((class_name.Length > 0) && (ret.ClassOffset > 0))
                {
                    buffer.ReadArray((ulong)ret.ClassOffset, class_name, 0, class_name.Length);
                }
                return new Tuple<KeyFullInformation, string>(ret, Encoding.Unicode.GetString(class_name));
            }
        }

        /// <summary>
        /// Get key last write time
        /// </summary>
        /// <returns>The last write time</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public DateTime LastWriteTime
        {
            get
            {
                return DateTime.FromFileTime(GetFullInfo().Item1.LastWriteTime.QuadPart);
            }
        }

        /// <summary>
        /// Get key subkey count
        /// </summary>
        /// <returns>The subkey count</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public int SubKeyCount
        {
            get
            {
                return GetFullInfo().Item1.SubKeys;
            }
        }

        /// <summary>
        /// Get key value count
        /// </summary>
        /// <returns>The key value count</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public int ValueCount
        {
            get
            {
                return GetFullInfo().Item1.Values;
            }
        }

        /// <summary>
        /// Get the key title index
        /// </summary>
        /// <returns>The key title index</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public int TitleIndex
        {
            get
            {
                return GetFullInfo().Item1.TitleIndex;
            }
        }

        /// <summary>
        /// Get the key class name
        /// </summary>
        /// <returns>The key class name</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public string ClassName
        {
            get
            {
                return GetFullInfo().Item2;
            }
        }

        /// <summary>
        /// Get the maximum key value name length
        /// </summary>
        /// <returns>The maximum key value name length</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public int MaxValueNameLength
        {
            get
            {
                return GetFullInfo().Item1.MaxValueNameLen;
            }
        }

        /// <summary>
        /// Get the maximum key value data length
        /// </summary>
        /// <returns>The maximum key value data length</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public int MaxValueDataLength
        {
            get
            {
                return GetFullInfo().Item1.MaxValueDataLen;
            }
        }

        /// <summary>
        /// Get the maximum subkey name length
        /// </summary>
        /// <returns>The maximum subkey name length</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public int MaxNameLength
        {
            get
            {
                return GetFullInfo().Item1.MaxNameLen;
            }
        }

        /// <summary>
        /// Get the maximum class name length
        /// </summary>
        /// <returns>The maximum class name length</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public int MaxClassLength
        {
            get
            {
                return GetFullInfo().Item1.MaxClassLen;
            }
        }

        /// <summary>
        /// Get the key path as a Win32 style one. If not possible returns
        /// the original path.
        /// </summary>
        public string Win32Path
        {
            get
            {
                return NtKeyUtils.NtKeyNameToWin32(FullPath);
            }
        }

        /// <summary>
        /// The disposition when the key was created.
        /// </summary>
        public KeyDisposition Disposition
        {
            get; private set;
        }
    }

    /// <summary>
    /// Utilities for registry keys.
    /// </summary>
    public static class NtKeyUtils
    {
        private static Dictionary<string, string> CreateWin32BaseKeys()
        {
            Dictionary<string, string> dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            dict.Add("HKLM", @"\Registry\Machine");
            dict.Add("HKEY_LOCAL_MACHINE", @"\Registry\Machine");
            dict.Add("HKU", @"\Registry\User");
            dict.Add("HKEY_USERS", @"\Registry\User");
            using (NtToken token = NtToken.OpenProcessToken())
            {
                string current_user = String.Format(@"\Registry\User\{0}", token.User.Sid);
                dict.Add("HKCU", current_user);
                dict.Add("HKEY_CURRENT_USER", current_user);
            }
            dict.Add("HKEY_CLASSES_ROOT", @"\Registry\Machine\Software\Classes");
            dict.Add("HKCR", @"\Registry\Machine\Software\Classes");
            return dict;
        }

        private static Dictionary<string, string> _win32_base_keys = CreateWin32BaseKeys();

        /// <summary>
        /// Convert a Win32 style keyname such as HKEY_LOCAL_MACHINE\Path into a native key path.
        /// </summary>
        /// <param name="path">The win32 style keyname to convert.</param>
        /// <returns>The converted keyname.</returns>
        /// <exception cref="NtException">Thrown if invalid name.</exception>
        public static string Win32KeyNameToNt(string path)
        {
            foreach (var pair in _win32_base_keys)
            {
                if (path.Equals(pair.Key, StringComparison.OrdinalIgnoreCase))
                {
                    return pair.Value;
                }
                else if (path.StartsWith(pair.Key + @"\", StringComparison.OrdinalIgnoreCase))
                {
                    return pair.Value + path.Substring(pair.Key.Length);
                }
            }
            throw new NtException(NtStatus.STATUS_OBJECT_NAME_INVALID);
        }

        class StringLengthComparer : IComparer<string>
        {
            public int Compare(string x, string y)
            {
                return y.Length - x.Length;
            }
        }

        /// <summary>
        /// Attempt to convert an NT style registry key name to Win32 form.
        /// If it's not possible to convert the function will return the 
        /// original form.
        /// </summary>
        /// <param name="nt_path">The NT path to convert.</param>
        /// <returns>The converted path, or original if it can't be converted.</returns>
        public static string NtKeyNameToWin32(string nt_path)
        {
            foreach (var pair in _win32_base_keys.OrderBy(p => p.Value, new StringLengthComparer()))
            {
                if (nt_path.Equals(pair.Value, StringComparison.OrdinalIgnoreCase))
                {
                    return pair.Key;
                }
                else if (nt_path.StartsWith(pair.Value + @"\", StringComparison.OrdinalIgnoreCase))
                {
                    return pair.Key + nt_path.Substring(pair.Value.Length);
                }
            }
            return nt_path;
        }
    }
}
