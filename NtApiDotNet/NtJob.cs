using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    [Flags]
    public enum JobAccessRights : uint
    {
        None = 0,
        AssignProcess = 0x1,
        SetAttributes = 0x2,
        Query = 0x4,
        Terminate = 0x8,
        SetSecurityAttributes = 0x10,
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
        public static extern NtStatus NtCreateJobObject(out SafeKernelObjectHandle JobHandle, JobAccessRights DesiredAccess, ObjectAttributes ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenJobObject(out SafeKernelObjectHandle JobHandle, JobAccessRights DesiredAccess, ObjectAttributes ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAssignProcessToJobObject(SafeKernelObjectHandle JobHandle, SafeKernelObjectHandle ProcessHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtTerminateJobObject(SafeKernelObjectHandle JobHandle, NtStatus ExitStatus);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryInformationJobObject(SafeKernelObjectHandle JobHandle, int JobInfoClass, IntPtr JobInformation, int JobInformationLength, out int ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetInformationJobObject(SafeKernelObjectHandle JobHandle, int JobInfoClass, IntPtr JobInformation, int JobInformationLength);
    }

    public class NtJob : NtObjectWithDuplicate<NtJob, GenericAccessRights>
    {
        internal NtJob(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        public static NtJob Create(string name, NtObject root)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle handle;
                StatusToNtException(NtSystemCalls.NtCreateJobObject(out handle, JobAccessRights.MaximumAllowed, obja));
                return new NtJob(handle);
            }
        }

        public void CreateSilo()
        {
            StatusToNtException(NtSystemCalls.NtSetInformationJobObject(Handle, 35, IntPtr.Zero, 0));
        }

        public static NtJob Open(string path, NtObject root, JobAccessRights access_rights)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle handle;
                StatusToNtException(NtSystemCalls.NtOpenJobObject(out handle, access_rights, obja));
                return new NtJob(handle);
            }
        }
    }
}
