//  Copyright 2016 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
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
            : this(root, info.Name.ToString(), info.TypeName.ToString())
        {
        }

        public ObjectDirectoryInformation(NtDirectory root, string name, string typename)
        {
            _root = root;
            Name = name;
            TypeName = typename;
        }

        public NtObject Open(GenericAccessRights access)
        {
            return NtObject.OpenWithType(TypeName, Name, _root, access);
        }

        public bool IsDirectory
        {
            get { return TypeName.Equals("directory", StringComparison.OrdinalIgnoreCase); }
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
            AddIntegrityLevel(NtSecurity.GetIntegritySid(il));
        }

        public void AddSids(IEnumerable<Sid> sids)
        {
            foreach (Sid sid in sids)
            {
                if (NtSecurity.IsIntegritySid(sid))
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

        public static BoundaryDescriptor CreateFromString(string descriptor)
        {
            string[] parts = descriptor.Split(new char[] { '@' }, 2);
            string obj_name = parts.Length > 1 ? parts[1] : parts[0];

            BoundaryDescriptor boundary = new BoundaryDescriptor(obj_name);

            if (parts.Length > 1)
            {
                boundary.AddSids(parts[0].Split(':').Select(s => new Sid(s)));
            }

            return boundary;
        }

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
        /// Open a directory object
        /// </summary>
        /// <param name="obj_attributes">The object attributes to use for the open call.</param>
        /// <param name="desired_access">Access rights for directory object</param>
        /// <returns>The directory object</returns>
        /// <exception cref="NtException">Throw on error</exception>
        public static NtDirectory Open(ObjectAttributes obj_attributes, DirectoryAccessRights desired_access)
        {
            SafeKernelObjectHandle handle;
            StatusToNtException(NtSystemCalls.NtOpenDirectoryObject(out handle, desired_access, obj_attributes));
            return new NtDirectory(handle);
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
                return Open(obja, desired_access);
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
        /// Create a directory object with a shadow
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create the directory with</param>
        /// <param name="desired_access">The desired access to the directory</param>
        /// <param name="shadow_dir">The shadow directory</param>
        /// <returns>The directory object</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public static NtDirectory Create(ObjectAttributes obj_attributes, DirectoryAccessRights desired_access, NtDirectory shadow_dir)
        {
            SafeKernelObjectHandle handle;
            if (shadow_dir == null)
            {
                StatusToNtException(NtSystemCalls.NtCreateDirectoryObject(out handle, desired_access, obj_attributes));
            }
            else
            {
                StatusToNtException(NtSystemCalls.NtCreateDirectoryObjectEx(out handle, desired_access, obj_attributes,
                    shadow_dir.Handle, 0));
            }
            return new NtDirectory(handle);
        }

        /// <summary>
        /// Create a directory object
        /// </summary>
        /// <param name="name">The directory object to create, if null will create a unnamed directory object</param>
        /// <param name="desired_access">The desired access to the directory</param>
        /// <param name="root">Root directory from where to start the creation operation</param>
        /// <returns>The directory object</returns>
        /// <exception cref="NtException">Thrown on error</exception>
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
        /// <exception cref="NtException">Thrown on error</exception>
        public static NtDirectory Create(string name, NtObject root, DirectoryAccessRights desired_access, NtDirectory shadow_dir)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, desired_access, shadow_dir);
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

        public static NtDirectory CreatePrivateNamespace(ObjectAttributes obj_attributes, BoundaryDescriptor boundary_descriptor, DirectoryAccessRights access)
        {
            SafeKernelObjectHandle handle;
            StatusToNtException(NtSystemCalls.NtCreatePrivateNamespace(out handle, access, obj_attributes, boundary_descriptor.Handle));
            NtDirectory ret = new NtDirectory(handle);
            ret._private_namespace = true;
            return ret;         
        }

        public static NtDirectory CreatePrivateNamespace(BoundaryDescriptor boundary_descriptor)
        {
            using (ObjectAttributes obja = new ObjectAttributes())
            {
                return CreatePrivateNamespace(obja, boundary_descriptor, DirectoryAccessRights.MaximumAllowed);
            }
        }

        public static NtDirectory OpenPrivateNamespace(ObjectAttributes obj_attributes, BoundaryDescriptor boundary_descriptor, DirectoryAccessRights access)
        {
            SafeKernelObjectHandle handle;
            StatusToNtException(NtSystemCalls.NtOpenPrivateNamespace(out handle, access, obj_attributes, boundary_descriptor.Handle));
            NtDirectory ret = new NtDirectory(handle);
            ret._private_namespace = true;
            return ret;
        }

        public static NtDirectory OpenPrivateNamespace(BoundaryDescriptor boundary_descriptor)
        {
            using (ObjectAttributes obja = new ObjectAttributes())
            {
                return OpenPrivateNamespace(obja, boundary_descriptor, DirectoryAccessRights.MaximumAllowed);
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

        public ObjectDirectoryInformation GetDirectoryEntry(string name, string typename, bool case_sensitive)
        {
            StringComparison comparison_type = case_sensitive ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
            foreach (ObjectDirectoryInformation dir_info in Query())
            {
                if (!dir_info.Name.Equals(name, comparison_type))
                {
                    continue;
                }

                if (typename != null && !typename.Equals(typename, comparison_type))
                {
                    continue;
                }

                return dir_info;
            }
            return null;
        }

        public ObjectDirectoryInformation GetDirectoryEntry(string name)
        {
            return GetDirectoryEntry(name, null, false);
        }

        /// <summary>
        /// Returns whether a directory exists for this path.
        /// </summary>
        /// <param name="path">The path to the entry.</param>
        /// <param name="root">The root directory.</param>
        /// <returns></returns>
        public static bool DirectoryExists(string path, NtDirectory root)
        {
            try
            {
                using (NtDirectory dir = NtDirectory.Open(path, root, DirectoryAccessRights.MaximumAllowed))
                {
                    return true;
                }
            }
            catch (NtException)
            {
                return false;
            }
        }

        private static string GetDirectoryName(string path)
        {
            int index = path.LastIndexOf('\\');
            if (index < 0)
            {
                return String.Empty;
            }
            else
            {
                return path.Substring(0, index);
            }
        }

        private static string GetFileName(string path)
        {
            int index = path.LastIndexOf('\\');
            if (index < 0)
            {
                return path;
            }
            else
            {
                return path.Substring(index + 1);
            }
        }

        public static string GetDirectoryEntryType(string name, NtObject root)
        {
            if (root == null && name == @"\")
            {
                return "Directory";
            }

            try
            {
                using (NtDirectory dir = NtDirectory.Open(GetDirectoryName(name), root, DirectoryAccessRights.Query))
                {
                    ObjectDirectoryInformation dir_info = dir.GetDirectoryEntry(GetFileName(name));
                    if (dir_info != null)
                    {
                        return dir_info.TypeName;
                    }
                }
            }
            catch (NtException)
            {
            }

            return null;
        }

        public bool DirectoryExists(string path)
        {
            return DirectoryExists(path, this);
        }

        private bool _private_namespace;
    }
}
