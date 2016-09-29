using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    [Flags]
    public enum MutantAccessRights : uint
    {
        None = 0,
        QueryState = 1,
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
        public static extern NtStatus NtCreateMutant(out SafeKernelObjectHandle MutantHandle, MutantAccessRights DesiredAccess, 
            ObjectAttributes ObjectAttributes, bool InitialOwner);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenMutant(out SafeKernelObjectHandle MutantHandle, MutantAccessRights DesiredAccess, 
            ObjectAttributes ObjectAttributes);
    }

    public class NtMutant : NtObjectWithDuplicate<NtMutant, MutantAccessRights>
    {
        internal NtMutant(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        public static NtMutant Create(string name, NtObject root, bool initial_owner)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle handle;
                StatusToNtException(NtSystemCalls.NtCreateMutant(out handle, MutantAccessRights.MaximumAllowed, obja, initial_owner));
                return new NtMutant(handle);
            }
        }

        public static NtMutant Open(string name, NtObject root, MutantAccessRights access_rights)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle handle;
                StatusToNtException(NtSystemCalls.NtOpenMutant(out handle, access_rights, obja));
                return new NtMutant(handle);
            }
        }
    }
}
