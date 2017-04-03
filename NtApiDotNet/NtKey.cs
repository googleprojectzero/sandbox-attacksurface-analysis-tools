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
          int      Index,
          KeyValueInformationClass KeyValueInformationClass,
          SafeBuffer KeyValueInformation,
          int      Length,
          out int  ResultLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryKey(
                SafeKernelObjectHandle KeyHandle,
                KeyInformationClass KeyInformationClass,
                SafeBuffer KeyInformation,
                int Length,
                out int ResultLength
            );
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
    public class NtKey : NtObjectWithDuplicate<NtKey, KeyAccessRights>
    {
        internal NtKey(SafeKernelObjectHandle handle) : base(handle)
        {
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
        /// <param name="key">Object attributes for the key name</param>
        /// <param name="file">Object attributes for the path to the hive file</param>
        /// <param name="flags">Load flags</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <returns>The opened root key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey LoadKey(ObjectAttributes key, ObjectAttributes file, LoadKeyFlags flags, KeyAccessRights desired_access)
        {
            SafeKernelObjectHandle key_handle;
            NtSystemCalls.NtLoadKeyEx(key, file, flags, 
                IntPtr.Zero, IntPtr.Zero, desired_access, out key_handle, 0).ToNtException();
            return new NtKey(key_handle);
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
            SafeKernelObjectHandle key;
            KeyDisposition disposition;
            NtSystemCalls.NtCreateKey(out key, desired_access, obj_attributes, 0, null, options, out disposition).ToNtException();
            return new NtKey(key);
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
        /// Open a Key
        /// </summary>
        /// <param name="obj_attributes">Object attributes for the key name</param>
        /// <param name="desired_access">Desired access for the root key</param>
        /// <returns>The opened key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey Open(ObjectAttributes obj_attributes, KeyAccessRights desired_access)
        {
            SafeKernelObjectHandle key;
            NtSystemCalls.NtOpenKey(out key, desired_access, obj_attributes).ToNtException();
            return new NtKey(key);
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
                return Open(obja, desired_access);
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
            NtSystemCalls.NtSetValueKey(Handle, new UnicodeString(value_name), 0, type, data, data.Length).ToNtException();
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
        /// <returns>The value information</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public NtKeyValue QueryValue(string value_name)
        {            
            UnicodeString name = new UnicodeString(value_name);
            int return_len = 0;
            int query_count = 0;

            while (query_count < 64)
            {
                using (var info = new SafeStructureInOutBuffer<KeyValuePartialInformation>(return_len, false))
                {
                    NtStatus status = NtSystemCalls.NtQueryValueKey(Handle, name, KeyValueInformationClass.KeyValuePartialInformation,
                        info, info.Length, out return_len);
                    if (status.IsSuccess())
                    {
                        KeyValuePartialInformation result = info.Result;                        
                        return new NtKeyValue(value_name, info.Result.Type, info.Data.ReadBytes(result.DataLength), result.TitleIndex);
                    }
                    if (status != NtStatus.STATUS_BUFFER_OVERFLOW && status != NtStatus.STATUS_BUFFER_TOO_SMALL)
                        status.ToNtException(); ;
                }
                query_count++;
            }
            throw new NtException(NtStatus.STATUS_BUFFER_TOO_SMALL);
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
        /// <returns>The disposable list of subkeys.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public DisposableList<NtKey> QueryAccessibleKeys(KeyAccessRights desired_access)
        {
            DisposableList<NtKey> ret = new DisposableList<NtKey>();

            foreach (string name in QueryKeys())
            {
                try
                {
                    ret.Add(Open(name, desired_access));
                }
                catch (NtException)
                {
                }
            }
            return ret;
        }

        /// <summary>
        /// Create a registry key symbolic link
        /// </summary>
        /// <param name="rootkey">Root key if path is relative</param>
        /// <param name="path">Path to the key to create</param>
        /// <param name="target">Target resistry path</param>
        /// <returns>The create symbolic key</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtKey CreateSymbolicLink(string path, NtKey rootkey, string target)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive | AttributeFlags.OpenIf | AttributeFlags.OpenLink, rootkey))
            {
                NtKey key = Create(obja, KeyAccessRights.MaximumAllowed, KeyCreateOptions.CreateLink);
                bool set_value = false;
                try
                {
                    key.SetValue("SymbolicLinkValue", RegistryValueType.Link, Encoding.Unicode.GetBytes(target));
                    set_value = true;
                    return key;
                }
                finally
                {
                    if (!set_value)
                    {
                        key.Delete();
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

        private static SafeRegistryHandle DuplicateAsRegistry(SafeHandle handle)
        {
            using (SafeKernelObjectHandle dup_handle = DuplicateHandle(NtProcess.Current, handle, NtProcess.Current))
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
        public int GetValueCount()
        {
            return GetFullInfo().Item1.Values;
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
    }
}
