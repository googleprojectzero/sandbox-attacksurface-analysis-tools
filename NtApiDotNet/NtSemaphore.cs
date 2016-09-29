using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    [Flags]
    public enum SemaphoreAccessRights : uint
    {
        None = 0,
        QueryState = 1,
        ModifyState = 2,
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
        public static extern NtStatus NtCreateSemaphore(out SafeKernelObjectHandle MutantHandle, SemaphoreAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes, int InitialCount, int MaximumCount);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenSemaphore(out SafeKernelObjectHandle MutantHandle, SemaphoreAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes);
    }

    public class NtSemaphore : NtObjectWithDuplicate<NtSemaphore, SemaphoreAccessRights>
    {
        internal NtSemaphore(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        public static NtSemaphore Create(string name, NtObject root, int initial_count, int maximum_count)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle handle;
                StatusToNtException(NtSystemCalls.NtCreateSemaphore(out handle, SemaphoreAccessRights.MaximumAllowed, obja, initial_count, maximum_count));
                return new NtSemaphore(handle);
            }
        }

        public static NtSemaphore Open(string name, NtObject root, SemaphoreAccessRights access_rights)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle handle;
                StatusToNtException(NtSystemCalls.NtOpenSemaphore(out handle, access_rights, obja));
                return new NtSemaphore(handle);
            }
        }
    }
}
