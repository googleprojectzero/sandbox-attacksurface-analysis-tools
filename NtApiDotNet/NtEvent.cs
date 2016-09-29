using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    public enum EventAccessRights : uint
    {
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
    public enum EventType
    {
        NotificationEvent,
        SynchronizationEvent
    }    

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateEvent(
            out SafeKernelObjectHandle EventHandle,
            EventAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes,
            EventType EventType,
            bool InitialState);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenEvent(
            out SafeKernelObjectHandle EventHandle,
            EventAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetEvent(
            SafeHandle EventHandle,
            out int PreviousState);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtClearEvent(
            SafeHandle EventHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtPulseEvent(
            SafeHandle EventHandle,
            out int PreviousState);
    }

    public class NtEvent : NtObjectWithDuplicate<NtEvent, EventAccessRights>
    {
        internal NtEvent(SafeKernelObjectHandle handle) 
            : base(handle)
        {
        }

        public int Set()
        {
            int previous_state;
            StatusToNtException(NtSystemCalls.NtSetEvent(Handle, out previous_state));
            return previous_state;
        }

        public void Clear()
        {            
            StatusToNtException(NtSystemCalls.NtClearEvent(Handle));            
        }

        public int Pulse()
        {
            int previous_state;
            StatusToNtException(NtSystemCalls.NtPulseEvent(Handle, out previous_state));
            return previous_state;
        }

        public static NtEvent Create(string name, NtObject root, EventType type, bool initial_state)
        {            
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle handle;
                StatusToNtException(NtSystemCalls.NtCreateEvent(out handle, EventAccessRights.MaximumAllowed, obja, type, initial_state));
                return new NtEvent(handle);
            }
        }

        public static NtEvent Create(string name, EventType type, bool initial_state)
        {
            return Create(name, null, type, initial_state);
        }

        public static NtEvent Open(string name, NtObject root, EventAccessRights access)
        {            
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle handle;
                StatusToNtException(NtSystemCalls.NtOpenEvent(out handle, access, obja));
                return new NtEvent(handle);
            }
        }

        public static NtEvent Open(string name, NtObject root)
        {
            return Open(name, root, EventAccessRights.MaximumAllowed);
        }

        public static NtEvent Open(string name)
        {
            return Open(name, null);
        }
    }
}
