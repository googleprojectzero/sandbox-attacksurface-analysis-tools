using System;

namespace HandleUtils
{
    public class HandleEntry
    {
        public int ProcessId { get; set; }
        public string ObjectName { get; set; }
        public string TypeName { get; set; }
        public IntPtr Handle { get; set; }
        public IntPtr Object { get; set; }
        public int ObjectTypeNumber { get; set; }
        public int Flags { get; set; }
        public uint GrantedAccess { get; set; }
        public bool HasName { get; set; }
        public byte[] SecurityDescriptor { get; set; }
        public string StringSecurityDescriptor { get; set; }
    }
}
