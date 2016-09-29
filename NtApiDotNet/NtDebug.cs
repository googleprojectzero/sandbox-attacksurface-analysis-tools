using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtDebugActiveProcess(SafeKernelObjectHandle ProcessHandle, SafeKernelObjectHandle DebugHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateDebugObject(out SafeKernelObjectHandle DebugHandle, GenericAccessRights DesiredAccess, ObjectAttributes ObjectAttributes, int Flags);
    }

    public class NtDebug : NtObjectWithDuplicate<NtDebug, GenericAccessRights>
    {
        internal NtDebug(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        public static NtDebug Create(string name, NtObject root)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle handle;
                StatusToNtException(NtSystemCalls.NtCreateDebugObject(out handle, GenericAccessRights.MaximumAllowed, obja, 0));
                return new NtDebug(handle);
            }
        }

        public static NtDebug Create()
        {
            return Create(null, null);
        }
    }
}
