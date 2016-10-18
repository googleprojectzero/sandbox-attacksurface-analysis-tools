using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace NtApiDotNet
{
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
        MaximumAllowed = GenericAccessRights.MaximumAllowed
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

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateKey(
            out SafeKernelObjectHandle KeyHandle,
            KeyAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes,
            int TitleIndex,
            UnicodeString Class,
            KeyCreateOptions CreateOptions,
            out KeyDisposition Disposition
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenKey(
            out SafeKernelObjectHandle KeyHandle,
            KeyAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes
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
        public static extern NtStatus NtOpenKeyTransacted(out SafeKernelObjectHandle KeyHandle, KeyAccessRights DesiredAccess, ObjectAttributes ObjectAttributes, SafeKernelObjectHandle TransactionHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenKeyTransactedEx(out SafeKernelObjectHandle KeyHandle, KeyAccessRights DesiredAccess, ObjectAttributes ObjectAttributes, int OpenOptions, SafeKernelObjectHandle TransactionHandle);

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
        public static extern NtStatus NtLoadKeyEx(ObjectAttributes DestinationName, ObjectAttributes FileName, LoadKeyFlags Flags,
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

    public class NtKeyValue
    {
        public string Name { get; private set; }
        public RegistryValueType Type { get; private set; }
        public byte[] Data { get; private set; }
        public int TitleIndex { get; private set; }
        public NtKeyValue(string name, RegistryValueType type, byte[] data, int title_index)
        {
            Name = name;
            Type = type;
            Data = data;
            TitleIndex = title_index;
        }

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
                    throw new ArgumentException("Value can't be converted to a string");
            }
        }

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

    public class NtKey : NtObjectWithDuplicate<NtKey, KeyAccessRights>
    {
        internal NtKey(SafeKernelObjectHandle handle) : base(handle)
        {
        }

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

        public static NtKey LoadKey(ObjectAttributes keyname, ObjectAttributes file, LoadKeyFlags flags, KeyAccessRights desired_access)
        {
            SafeKernelObjectHandle key;
            StatusToNtException(NtSystemCalls.NtLoadKeyEx(keyname, file, flags, 
                IntPtr.Zero, IntPtr.Zero, desired_access, out key, 0));
            return new NtKey(key);
        }

        public static NtKey Create(ObjectAttributes obj_attributes, KeyAccessRights access, KeyCreateOptions options)
        {
            SafeKernelObjectHandle key;
            KeyDisposition disposition;
            StatusToNtException(NtSystemCalls.NtCreateKey(out key, access, obj_attributes, 0, null, options, out disposition));
            return new NtKey(key);
        }

        public static NtKey Create(string key_name, NtObject root, KeyAccessRights access, KeyCreateOptions options)
        {
            using (ObjectAttributes obja = new ObjectAttributes(key_name, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, access, options);
            }
        }

        public NtKey Create(string key_name)
        {
            return Create(key_name, this, KeyAccessRights.MaximumAllowed, KeyCreateOptions.NonVolatile);
        }

        public NtKey Create(string key_name, KeyAccessRights access, KeyCreateOptions options)
        {
            return Create(key_name, this, access, options);
        }

        public static NtKey Open(ObjectAttributes obj_attributes, KeyAccessRights access)
        {
            SafeKernelObjectHandle key;
            StatusToNtException(NtSystemCalls.NtOpenKey(out key, access, obj_attributes));
            return new NtKey(key);
        }

        public static NtKey Open(string key_name, NtObject root, KeyAccessRights access)
        {
            using (ObjectAttributes obja = new ObjectAttributes(key_name, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obja, access);
            }
        }
        
        public void Delete()
        {
            StatusToNtException(NtSystemCalls.NtDeleteKey(Handle));            
        }

        public void SetValue(string value_name, RegistryValueType type, byte[] data)
        {            
            StatusToNtException(NtSystemCalls.NtSetValueKey(Handle, new UnicodeString(value_name), 0, type, data, data.Length));            
        }

        public void SetValue(string value_name, RegistryValueType type, string data)
        {
            SetValue(value_name, type, Encoding.Unicode.GetBytes(data));
        }

        public void SetValue(string value_name, uint data)
        {
            SetValue(value_name, RegistryValueType.Dword, BitConverter.GetBytes(data));
        }

        public void SetValue(string value_name, ulong data)
        {
            SetValue(value_name, RegistryValueType.Qword, BitConverter.GetBytes(data));
        }

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
                    if (IsSuccess(status))
                    {
                        KeyValuePartialInformation result = info.Result;                        
                        return new NtKeyValue(value_name, info.Result.Type, info.Data.ReadBytes(result.DataLength), result.TitleIndex);
                    }
                    if (status != NtStatus.STATUS_BUFFER_OVERFLOW && status != NtStatus.STATUS_BUFFER_TOO_SMALL)
                        StatusToNtException(status);
                }
                query_count++;
            }
            throw new NtException(NtStatus.STATUS_BUFFER_TOO_SMALL);
        }

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

        public static NtKey CreateSymbolicLink(NtKey rootkey, string path, string target)
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

        public NtKey Open(string key_name)
        {
            return Open(key_name, this, KeyAccessRights.MaximumAllowed);
        }

        public NtKey Open(string key_name, KeyAccessRights access)
        {
            return Open(key_name, this, access);
        }

        public static NtKey GetMachineKey()
        {
            return Open(@"\Registry\Machine", null, KeyAccessRights.MaximumAllowed);
        }

        public static NtKey GetUserKey()
        {
            return Open(@"\Registry\User", null, KeyAccessRights.MaximumAllowed);
        }

        public static NtKey GetUserKey(Sid sid)
        {
            return Open(@"\Registry\User\" + sid.ToString(), null, KeyAccessRights.MaximumAllowed);
        }

        public static NtKey GetCurrentUserKey()
        {
            return GetUserKey(NtToken.GetCurrentUser().Sid);
        }

        public static NtKey GetRootKey()
        {
            return Open(@"\Registry", null, KeyAccessRights.MaximumAllowed);
        }

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

        public DateTime GetLastWriteTime()
        {
            return DateTime.FromFileTime(GetFullInfo().Item1.LastWriteTime.QuadPart);
        }

        public int GetSubKeyCount()
        {
            return GetFullInfo().Item1.SubKeys;
        }

        public int GetValueCount()
        {
            return GetFullInfo().Item1.Values;
        }

        public int GetTitleIndex()
        {
            return GetFullInfo().Item1.TitleIndex;
        }

        public string GetClassName()
        {
            return GetFullInfo().Item2;
        }

        public int GetMaxValueNameLength()
        {
            return GetFullInfo().Item1.MaxValueNameLen;
        }

        public int GetMaxValueDataLength()
        {
            return GetFullInfo().Item1.MaxValueDataLen;
        }

        public int GetMaxNameLength()
        {
            return GetFullInfo().Item1.MaxNameLen;
        }

        public int GetMaxClassLength()
        {
            return GetFullInfo().Item1.MaxClassLen;
        }
    }
}
