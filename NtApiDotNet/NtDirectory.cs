using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_DIRECTORY_INFORMATION
    {
        public UnicodeStringOut Name;
        public UnicodeStringOut TypeName;
    }

    public class ObjectDirectoryInformation
    {
        private NtDirectory _root;

        public string Name { get; private set; }
        public string TypeName { get; private set; }

        internal ObjectDirectoryInformation(NtDirectory root, OBJECT_DIRECTORY_INFORMATION info)
        {
            _root = root;
            Name = info.Name.ToString();
            TypeName = info.TypeName.ToString();
        }

        public NtObject Open(GenericAccessRights access)
        {
            return NtObject.OpenWithType(TypeName, Name, _root, access);
        }
    }

    [Flags]
    public enum DirectoryAccessRights : uint
    {
        Query = 1,
        Traverse = 2,
        CreateObject = 4,
        CreateSubDirectory = 8,
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

    [Flags]
    public enum BoundaryDescriptorFlags
    {
        None = 0,
        AddPackageSid = 1,
    }

    public sealed class BoundaryDescriptor : IDisposable
    {
        private IntPtr _boundary_descriptor;

        public BoundaryDescriptor(string name, BoundaryDescriptorFlags flags)
        {
            _boundary_descriptor = NtRtl.RtlCreateBoundaryDescriptor(new UnicodeString(name), flags);
            if (_boundary_descriptor == IntPtr.Zero)
            {
                throw new NtException(NtStatus.STATUS_MEMORY_NOT_ALLOCATED);
            }
        }

        public BoundaryDescriptor(string name) : this(name, BoundaryDescriptorFlags.None)
        {
        }

        public void AddSid(Sid sid)
        {
            using (SafeSidBufferHandle sid_buffer = sid.ToSafeBuffer())
            {
                NtObject.StatusToNtException(NtRtl.RtlAddSIDToBoundaryDescriptor(ref _boundary_descriptor, sid_buffer));
            }            
        }

        private void AddIntegrityLevel(Sid sid)
        {
            using (SafeSidBufferHandle sid_buffer = sid.ToSafeBuffer())
            {
                NtObject.StatusToNtException(NtRtl.RtlAddIntegrityLabelToBoundaryDescriptor(ref _boundary_descriptor, sid_buffer));
            }
        }

        public void AddIntegrityLevel(TokenIntegrityLevel il)
        {
            AddIntegrityLevel(Sid.GetIntegritySid(il));
        }

        public void AddSids(IEnumerable<Sid> sids)
        {
            foreach (Sid sid in sids)
            {
                if (Sid.IsIntegritySid(sid))
                {
                    AddIntegrityLevel(sid);
                }
                else
                {
                    AddSid(sid);
                }
            }
        }

        public void AddSids(params Sid[] sids)
        {
            AddSids((IEnumerable<Sid>)sids);
        }
        
        public IntPtr Handle { get { return _boundary_descriptor; } }

        #region IDisposable Support
    private bool disposedValue = false; // To detect redundant calls

        void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                NtRtl.RtlDeleteBoundaryDescriptor(_boundary_descriptor);
                disposedValue = true;
            }
        }

        ~BoundaryDescriptor()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(false);
        }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {            
            Dispose(true);        
            GC.SuppressFinalize(this);
        }
        #endregion
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateDirectoryObject(out SafeKernelObjectHandle Handle, 
            DirectoryAccessRights DesiredAccess, ObjectAttributes ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateDirectoryObjectEx(out SafeKernelObjectHandle Handle, 
            DirectoryAccessRights DesiredAccess, ObjectAttributes ObjectAttributes, SafeKernelObjectHandle ShadowDirectory, int Flags);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenDirectoryObject(out SafeKernelObjectHandle Handle, DirectoryAccessRights DesiredAccess, ObjectAttributes ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryDirectoryObject(SafeKernelObjectHandle DirectoryHandle, 
            SafeBuffer Buffer, int Length, bool ReturnSingleEntry, bool RestartScan, ref int Context, out int ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreatePrivateNamespace(
            out SafeKernelObjectHandle NamespaceHandle,
            DirectoryAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes,
            IntPtr BoundaryDescriptor);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenPrivateNamespace(
            out SafeKernelObjectHandle NamespaceHandle,
            DirectoryAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes,
            IntPtr BoundaryDescriptor);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtDeletePrivateNamespace(
            [In] SafeKernelObjectHandle NamespaceHandle
        );
    }

    public static partial class NtRtl
    {
        [DllImport("ntdll.dll")]
        public static extern IntPtr RtlCreateBoundaryDescriptor([In] UnicodeString Name, BoundaryDescriptorFlags Flags);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlAddSIDToBoundaryDescriptor(ref IntPtr BoundaryDescriptor, SafeSidBufferHandle RequiredSid);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlAddIntegrityLabelToBoundaryDescriptor(ref IntPtr BoundaryDescriptor, SafeSidBufferHandle RequiredSid);

        [DllImport("ntdll.dll")]
        public static extern bool RtlDeleteBoundaryDescriptor(IntPtr BoundaryDescriptor);
    }

    /// <summary>
    /// NT Directory Object class
    /// </summary>
    public class NtDirectory : NtObjectWithDuplicate<NtDirectory, DirectoryAccessRights>
    {
        internal NtDirectory(SafeKernelObjectHandle handle) : base(handle)
        {            
        }
        
        /// <summary>
        /// Open a directory object by name
        /// </summary>
        /// <param name="name">The directory object to open</param>
        /// <param name="root">Optional root directory to parse from</param>
        /// <param name="desired_access">Access rights for directory object</param>
        /// <returns>The directory object</returns>
        /// <exception cref="NtException">Throw on error</exception>
        public static NtDirectory Open(string name, NtObject root, DirectoryAccessRights desired_access)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle handle;
                StatusToNtException(NtSystemCalls.NtOpenDirectoryObject(out handle, desired_access, obja));
                return new NtDirectory(handle);
            }
        }

        /// <summary>
        /// Open a directory object by full name
        /// </summary>
        /// <param name="name">The directory object to open</param>
        /// <returns>The directory object</returns>
        /// <exception cref="NtException">Throw on error</exception>
        public static NtDirectory Open(string name)
        {
            return Open(name, null, DirectoryAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Create a directory object
        /// </summary>
        /// <param name="name">The directory object to create, if null will create a unnamed directory object</param>
        /// <param name="desired_access">The desired access to the directory</param>
        /// <param name="root">Root directory from where to start the creation operation</param>
        /// <returns>The directory object</returns>
        /// <exception cref="NtException">Throw on error</exception>
        public static NtDirectory Create(string name, NtObject root, DirectoryAccessRights desired_access)
        {
            return Create(name, root, desired_access, null);
        }

        /// <summary>
        /// Create a directory object with a shadow
        /// </summary>
        /// <param name="name">The directory object to create, if null will create a unnamed directory object</param>
        /// <param name="desired_access">The desired access to the directory</param>
        /// <param name="root">Root directory from where to start the creation operation</param>
        /// <param name="shadow_dir">The shadow directory</param>
        /// <returns>The directory object</returns>
        /// <exception cref="NtException">Throw on error</exception>
        public static NtDirectory Create(string name, NtObject root, DirectoryAccessRights desired_access, NtDirectory shadow_dir)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle handle;
                StatusToNtException(NtSystemCalls.NtCreateDirectoryObjectEx(out handle, desired_access, obja, 
                    shadow_dir != null ? shadow_dir.Handle : SafeKernelObjectHandle.Null, 0));
                return new NtDirectory(handle);
            }
        }

        public static NtDirectory Create(string name)
        {
            return Create(name, null, DirectoryAccessRights.MaximumAllowed);
        }

        public IEnumerable<ObjectDirectoryInformation> Query()
        {
            using (SafeStructureInOutBuffer<OBJECT_DIRECTORY_INFORMATION> buffer
                = new SafeStructureInOutBuffer<OBJECT_DIRECTORY_INFORMATION>(ushort.MaxValue * 2, true))
            {
                int context = 0;
                int return_length = 0;
                NtStatus status = NtSystemCalls.NtQueryDirectoryObject(Handle, buffer, buffer.Length, 
                    true, true, ref context, out return_length);
                while (status == NtStatus.STATUS_SUCCESS)
                {
                    yield return new ObjectDirectoryInformation(this, buffer.Result);
                    status = NtSystemCalls.NtQueryDirectoryObject(Handle, buffer, buffer.Length, 
                        true, false, ref context, out return_length);
                }
            }
        }

        public static NtDirectory OpenSessionDirectory(int sessionid)
        {
            return Open(String.Format(@"\Sessions\{0}", sessionid));
        }

        public static NtDirectory OpenSessionDirectory()
        {
            return OpenSessionDirectory(NtProcess.Current.GetProcessSessionId());
        }

        public static NtDirectory OpenBaseNamedObjects(int sessionid)
        {
            if (sessionid == 0)
            {
                return Open(@"\BaseNamedObjects");
            }
            else
            {
                return Open(String.Format(@"\Sessions\{0}\BaseNamedObjects", sessionid));
            }
        }

        public static NtDirectory OpenBaseNamedObjects()
        {
            return OpenBaseNamedObjects(NtProcess.Current.GetProcessSessionId());
        }

        public static NtDirectory OpenDosDevicesDirectory(NtToken token)
        {
            Luid authid = token.GetAuthenticationId();
            if (authid.Equals(NtToken.LocalSystemAuthId))
            {
                return NtDirectory.Open(@"\GLOBAL??");
            }

            return NtDirectory.Open(String.Format(@"\Sessions\0\DosDevices\{0:X08}-{1:X08}", authid.HighPart, authid.LowPart));
        }

        public static NtDirectory OpenDosDevicesDirectory()
        {
            using (NtToken token = NtToken.OpenEffectiveToken())
            {
                return OpenDosDevicesDirectory(token);
            }
        }

        public static NtDirectory CreatePrivateNamespace(BoundaryDescriptor boundary_descriptor)
        {
            using (ObjectAttributes obja = new ObjectAttributes())
            {
                SafeKernelObjectHandle handle;
                StatusToNtException(NtSystemCalls.NtCreatePrivateNamespace(out handle, DirectoryAccessRights.MaximumAllowed, obja, boundary_descriptor.Handle));
                NtDirectory ret = new NtDirectory(handle);
                ret._private_namespace = true;
                return ret;
            }
        }

        public static NtDirectory OpenPrivateNamespace(BoundaryDescriptor boundary_descriptor)
        {
            using (ObjectAttributes obja = new ObjectAttributes())
            {
                SafeKernelObjectHandle handle;
                StatusToNtException(NtSystemCalls.NtOpenPrivateNamespace(out handle, DirectoryAccessRights.MaximumAllowed, obja, boundary_descriptor.Handle));
                NtDirectory ret = new NtDirectory(handle);
                ret._private_namespace = true;
                return ret;
            }
        }

        /// <summary>
        /// Deletes a private namespace. If not a private namespace this does nothing.
        /// </summary>
        public void Delete()
        {
            if (_private_namespace)
            {
                StatusToNtException(NtSystemCalls.NtDeletePrivateNamespace(Handle));
            }
        }

        private bool _private_namespace;
    }
}
