using Microsoft.Win32;
using System;
using System.Runtime.InteropServices;
using System.Text;

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
    }

    public class NtKeyValue
    {
        public string Name { get; private set; }
        public RegistryValueType Type { get; private set; }
        public byte[] Data { get; private set; }
        public NtKeyValue(string name, RegistryValueType type, byte[] data)
        {
            Name = name;
            Type = type;
            Data = data;
        }

        public string AsString()
        {
            switch (Type)
            {
                case RegistryValueType.String:
                case RegistryValueType.ExpandString:
                case RegistryValueType.MultiString:
                    break;
                default:
                    throw new ArgumentException("Value is not a string");
            }
            return Encoding.Unicode.GetString(Data);
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

    public class NtKey : NtObjectWithDuplicate<NtKey, KeyAccessRights>
    {
        internal NtKey(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        public NtKey LoadKey(string destination, string filename, LoadKeyFlags flags)
        {
            using (ObjectAttributes dest = new ObjectAttributes(destination, AttributeFlags.CaseInsensitive))
            {
                using (ObjectAttributes name = new ObjectAttributes(filename, AttributeFlags.CaseInsensitive))
                {
                    SafeKernelObjectHandle key;
                    StatusToNtException(NtSystemCalls.NtLoadKeyEx(dest, name, flags, IntPtr.Zero, IntPtr.Zero, KeyAccessRights.MaximumAllowed, out key, 0));
                    return new NtKey(key);
                }
            }
        }

        public static NtKey Create(string key_name, NtKey root, AttributeFlags flags, KeyAccessRights access, KeyCreateOptions options)
        {
            using (ObjectAttributes obja = new ObjectAttributes(key_name, flags, root))
            {
                SafeKernelObjectHandle key;
                KeyDisposition disposition;
                StatusToNtException(NtSystemCalls.NtCreateKey(out key, access, obja, 0, null, options, out disposition));
                return new NtKey(key);
            }
        }

        public static NtKey Create(string key_name, NtKey root, KeyAccessRights access, KeyCreateOptions options)
        {
            return Create(key_name, root, AttributeFlags.CaseInsensitive | AttributeFlags.OpenIf, access, options);
        }

        public NtKey Create(string key_name)
        {
            return Create(key_name, this, KeyAccessRights.MaximumAllowed, KeyCreateOptions.NonVolatile);
        }

        public NtKey Create(string key_name, KeyAccessRights access, KeyCreateOptions options)
        {
            return Create(key_name, this, access, options);
        }

        public static NtKey Open(string key_name, NtKey root, KeyAccessRights access)
        {
            using (ObjectAttributes obja = new ObjectAttributes(key_name, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle key;
                StatusToNtException(NtSystemCalls.NtOpenKey(out key, access, obja));
                return new NtKey(key);
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
                        return new NtKeyValue(value_name, info.Result.Type, info.Data.ReadBytes(result.DataLength));
                    }
                    if (status != NtStatus.STATUS_BUFFER_OVERFLOW && status != NtStatus.STATUS_BUFFER_TOO_SMALL)
                        StatusToNtException(status);
                }
                query_count++;
            }
            throw new NtException(NtStatus.STATUS_BUFFER_TOO_SMALL);
        }

        public static NtKey CreateSymbolicLink(NtKey rootkey, string path, string target)
        {
            NtKey key = Create(path, rootkey, AttributeFlags.CaseInsensitive | AttributeFlags.OpenIf | AttributeFlags.OpenLink, 
                KeyAccessRights.MaximumAllowed, KeyCreateOptions.CreateLink);
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
    }
}
