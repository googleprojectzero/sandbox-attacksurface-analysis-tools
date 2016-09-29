using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    [Flags]
    public enum SymbolicLinkAccessRights : uint
    {
        Query = 1,        
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
        public static extern NtStatus NtCreateSymbolicLinkObject(
            out SafeKernelObjectHandle LinkHandle,
            SymbolicLinkAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes,
            UnicodeString DestinationName
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenSymbolicLinkObject(
            out SafeKernelObjectHandle LinkHandle,
            SymbolicLinkAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQuerySymbolicLinkObject(
            SafeHandle LinkHandle,
            [In, Out] UnicodeStringAllocated LinkTarget,
            out int ReturnedLength
        );
    }

    public class NtSymbolicLink : NtObjectWithDuplicate<NtSymbolicLink, SymbolicLinkAccessRights>
    {
        public NtSymbolicLink(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        public static NtSymbolicLink Create(string path, NtObject root, SymbolicLinkAccessRights access, string target)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle handle;
                StatusToNtException(NtSystemCalls.NtCreateSymbolicLinkObject(out handle,
                    access, obja, new UnicodeString(target)));
                return new NtSymbolicLink(handle);
            }
        }

        public static NtSymbolicLink Create(string path, NtObject root, string target)
        {
            return Create(path, root, SymbolicLinkAccessRights.MaximumAllowed, target);
        }

        public static NtSymbolicLink Create(string path, string target)
        {
            return Create(path, null, SymbolicLinkAccessRights.MaximumAllowed, target);
        }

        public static NtSymbolicLink Open(string path, NtObject root, SymbolicLinkAccessRights access)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle handle;
                StatusToNtException(NtSystemCalls.NtOpenSymbolicLinkObject(out handle,
                    access, obja));
                return new NtSymbolicLink(handle);
            }
        }

        public static NtSymbolicLink Open(string path, NtObject root)
        {
            return Open(path, root, SymbolicLinkAccessRights.MaximumAllowed);
        }

        public string Query()
        {
            using (UnicodeStringAllocated ustr = new UnicodeStringAllocated())
            {
                int return_length;
                StatusToNtException(NtSystemCalls.NtQuerySymbolicLinkObject(Handle, ustr, out return_length));
                return ustr.ToString();
            }
        }
    }
}
