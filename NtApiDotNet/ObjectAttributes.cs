using System;
using System.Runtime.InteropServices;

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
        SafeKernelObjectHandle RootDirectory;
        SafeBuffer ObjectName;
        AttributeFlags Attributes;
        SafeBuffer SecurityDescriptor;
        SafeBuffer SecurityQualityOfService;

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
            SecurityQualityOfService sqos, SecurityDescriptor security_descriptor)
        {
            Length = Marshal.SizeOf(this);
            if (object_name != null)
            {
                ObjectName = new UnicodeString(object_name).ToBuffer();
            }
            else
            {
                ObjectName = SafeHGlobalBuffer.Null;
            }

            Attributes = attributes;
            if (sqos != null)
            {
                SecurityQualityOfService = sqos.ToBuffer();
            }
            else
            {
                SecurityQualityOfService = SafeHGlobalBuffer.Null; 
            }

            RootDirectory = !root.IsInvalid ? NtObject.DuplicateHandle(root) : SafeKernelObjectHandle.Null;
            if (security_descriptor != null)
            {
                SecurityDescriptor = security_descriptor.ToSafeBuffer();
            }
            else
            {
                SecurityDescriptor = SafeHGlobalBuffer.Null;
            }
        }

        public ObjectAttributes(string object_name, AttributeFlags attributes, NtObject root, 
            SecurityQualityOfService sqos, SecurityDescriptor security_descriptor) 
            : this(object_name, attributes, root != null ? root.Handle : SafeKernelObjectHandle.Null, sqos, security_descriptor)
        {            
        }

        public void Dispose()
        {
            ObjectName.Close();
            SecurityQualityOfService.Close();
            SecurityDescriptor.Close();
            RootDirectory.Close();
            GC.SuppressFinalize(this);
        }

        ~ObjectAttributes()
        {
            Dispose();
        }
    }
}
