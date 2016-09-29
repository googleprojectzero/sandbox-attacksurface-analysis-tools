using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

namespace NtApiDotNet
{
    /// <summary>
    /// Flags for OBJECT_ATTRIBUTES
    /// </summary>
    [Flags]
    public enum AttributeFlags : uint
    {
        None = 0,
        Inherit = 0x00000002,
        Permanent = 0x00000010,
        Exclusive = 0x00000020,
        CaseInsensitive = 0x00000040,
        OpenIf = 0x00000080,
        OpenLink = 0x00000100,
        KernelHandle = 0x00000200,
        ForceAccessCheck = 0x00000400,
        IgnoreImpersonatedDevicemap = 0x00000800,
        DontReparse = 0x00001000,
    }

    /// <summary>
    /// A class which represents OBJECT_ATTRIBUTES
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public sealed class ObjectAttributes : IDisposable
    {
        int Length;
        //IntPtr RootDirectory;
        SafeKernelObjectHandle RootDirectory;
        IntPtr ObjectName;
        AttributeFlags Attributes;
        IntPtr SecurityDescriptor;
        IntPtr SecurityQualityOfService;

        private static IntPtr AllocStruct(object s)
        {
            int size = Marshal.SizeOf(s);
            IntPtr ret = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(s, ret, false);
            return ret;
        }

        private static void FreeStruct(ref IntPtr p, Type struct_type)
        {
            Marshal.DestroyStructure(p, struct_type);
            Marshal.FreeHGlobal(p);
            p = IntPtr.Zero;
        }

        public ObjectAttributes() : this(AttributeFlags.None)
        {
        }

        public ObjectAttributes(string object_name, AttributeFlags attributes) 
            : this(object_name, attributes, SafeKernelObjectHandle.Null, null, null)
        {
        }

        public ObjectAttributes(string object_name, AttributeFlags attributes, NtObject root) 
            : this(object_name, attributes, root, null, null)
        {
        }

        public ObjectAttributes(AttributeFlags attributes) 
            : this(null, attributes, SafeKernelObjectHandle.Null, null, null)
        {
        }

        public ObjectAttributes(string object_name) : this(object_name, AttributeFlags.CaseInsensitive, SafeKernelObjectHandle.Null, null, null)
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="object_name">The object name, can be null.</param>
        /// <param name="attributes">The object attribute flags.</param>
        /// <param name="root">An optional root handle, can be SafeKernelObjectHandle.Null. Will duplicate the handle.</param>
        /// <param name="sqos">An optional security quality of service.</param>
        /// <param name="security_descriptor">An optional security descriptor.</param>
        public ObjectAttributes(string object_name, AttributeFlags attributes, SafeKernelObjectHandle root, 
            SecurityQualityOfService sqos, GenericSecurityDescriptor security_descriptor)
        {
            Length = Marshal.SizeOf(this);
            if (object_name != null)
            {
                ObjectName = AllocStruct(new UnicodeString(object_name));
            }
            Attributes = attributes;
            if (sqos != null)
            {
                SecurityQualityOfService = AllocStruct(sqos);
            }
            RootDirectory = !root.IsInvalid ? NtObject.DuplicateHandle(root) : SafeKernelObjectHandle.Null;
            if (security_descriptor != null)
            {
                byte[] sd_binary = new byte[security_descriptor.BinaryLength];
                security_descriptor.GetBinaryForm(sd_binary, 0);
                SecurityDescriptor = Marshal.AllocHGlobal(sd_binary.Length);
                Marshal.Copy(sd_binary, 0, SecurityDescriptor, sd_binary.Length);
            }
        }

        public ObjectAttributes(string object_name, AttributeFlags attributes, NtObject root, 
            SecurityQualityOfService sqos, GenericSecurityDescriptor security_descriptor) 
            : this(object_name, attributes, root != null ? root.Handle : SafeKernelObjectHandle.Null, sqos, security_descriptor)
        {            
        }

        public void Dispose()
        {
            if (ObjectName != IntPtr.Zero)
            {
                FreeStruct(ref ObjectName, typeof(UnicodeString));
            }
            if (SecurityQualityOfService != IntPtr.Zero)
            {
                FreeStruct(ref SecurityQualityOfService, typeof(SecurityQualityOfService));
            }
            if (SecurityDescriptor != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(SecurityDescriptor);
                SecurityDescriptor = IntPtr.Zero;
            }
            if (!RootDirectory.IsInvalid)
            {
                RootDirectory.Close();
            }         
            GC.SuppressFinalize(this);
        }

        ~ObjectAttributes()
        {
            Dispose();
        }
    }
}
