using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    public enum RegistryTransactionAccessRights : uint
    {
        QueryInformation = 0x01,
        SetInformation = 0x02,
        Enlist = 0x04,
        Commit = 0x08,
        Rollback = 0x10,
        Propagate = 0x20,
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
    }

    public static partial class NtSystemCalls
    {        
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateRegistryTransaction(out SafeKernelObjectHandle Handle, RegistryTransactionAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes, int Flags);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenRegistryTransaction(out SafeKernelObjectHandle Handle, RegistryTransactionAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCommitRegistryTransaction(SafeKernelObjectHandle Handle, int Flags);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRollbackRegistryTransaction(SafeKernelObjectHandle Handle, int Flags);        
    }

    public class NtRegistryTransaction : NtObjectWithDuplicate<NtRegistryTransaction, RegistryTransactionAccessRights>
    {
        internal NtRegistryTransaction(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        public static NtRegistryTransaction Create(string name, NtObject root)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle handle;
                StatusToNtException(NtSystemCalls.NtCreateRegistryTransaction(out handle,
                    RegistryTransactionAccessRights.MaximumAllowed, obja, 0));
                return new NtRegistryTransaction(handle);
            }
        }

        public static NtRegistryTransaction Create(string name)
        {
            return Create(name, null);
        }

        public static NtRegistryTransaction Create()
        {
            return Create(null, null);
        }

        public static NtRegistryTransaction Open(string name, NtObject root, RegistryTransactionAccessRights access)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle handle;
                StatusToNtException(NtSystemCalls.NtOpenRegistryTransaction(out handle, access, obja));
                return new NtRegistryTransaction(handle);
            }
        }

        public static NtRegistryTransaction Open(string name)
        {
            return Open(name, null, RegistryTransactionAccessRights.MaximumAllowed);
        }

        public void Commit()
        {
            StatusToNtException(NtSystemCalls.NtCommitRegistryTransaction(Handle, 0));
        }
        public void Rollback()
        {
            StatusToNtException(NtSystemCalls.NtRollbackRegistryTransaction(Handle, 0));
        }
    }

}
