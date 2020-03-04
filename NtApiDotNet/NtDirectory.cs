//  Copyright 2016 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
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
    /// <summary>
    /// NT Directory Object class
    /// </summary>
    [NtType("Directory")]
    public class NtDirectory : NtObjectWithDuplicate<NtDirectory, DirectoryAccessRights>
    {
        #region Constructors

        internal NtDirectory(SafeKernelObjectHandle handle) 
            : this(handle, false)
        {
        }

        internal NtDirectory(SafeKernelObjectHandle handle, bool private_namespace) : base(handle)
        {
            _private_namespace = private_namespace;
        }

        internal sealed class NtTypeFactoryImpl : NtTypeFactoryImplBase
        {
            public NtTypeFactoryImpl() : base(true)
            {
            }

            protected override sealed NtResult<NtDirectory> OpenInternal(ObjectAttributes obj_attributes, 
                DirectoryAccessRights desired_access, bool throw_on_error)
            {
                return NtDirectory.Open(obj_attributes, desired_access, throw_on_error);
            }
        }
        #endregion

        #region Static Methods

        /// <summary>
        /// Open a directory object
        /// </summary>
        /// <param name="obj_attributes">The object attributes to use for the open call.</param>
        /// <param name="desired_access">Access rights for directory object</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        /// <exception cref="NtException">Thrown on error and throw_on_error is true.</exception>
        public static NtResult<NtDirectory> Open(ObjectAttributes obj_attributes, DirectoryAccessRights desired_access, bool throw_on_error)
        {
            return NtSystemCalls.NtOpenDirectoryObject(out SafeKernelObjectHandle handle, 
                desired_access, obj_attributes).CreateResult(throw_on_error, () => new NtDirectory(handle, false));
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
            return Open(obj_attributes, desired_access, true).Result;
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
            return Open(name, root, desired_access, true).Result;
        }

        /// <summary>
        /// Open a directory object by name
        /// </summary>
        /// <param name="name">The directory object to open</param>
        /// <param name="root">Optional root directory to parse from</param>
        /// <param name="desired_access">Access rights for directory object</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The directory object</returns>
        /// <exception cref="NtException">Throw on error</exception>
        public static NtResult<NtDirectory> Open(string name, NtObject root, 
            DirectoryAccessRights desired_access, bool throw_on_error)
        {
            using (var obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obja, desired_access, throw_on_error);
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
        /// <param name="flags">Flags for creation.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        /// <exception cref="NtException">Thrown on error and throw_on_error is true.</exception>
        public static NtResult<NtDirectory> Create(ObjectAttributes obj_attributes, DirectoryAccessRights desired_access, 
            NtDirectory shadow_dir, DirectoryCreateFlags flags, bool throw_on_error)
        {
            SafeKernelObjectHandle handle;
            NtStatus status;
            if (shadow_dir == null && flags == DirectoryCreateFlags.None)
            {
                status = NtSystemCalls.NtCreateDirectoryObject(out handle, desired_access, obj_attributes);
            }
            else
            {
                status = NtSystemCalls.NtCreateDirectoryObjectEx(out handle, desired_access, obj_attributes,
                    shadow_dir.GetHandle(), flags);
            }
            return status.CreateResult(throw_on_error, () => new NtDirectory(handle, false));
        }

        /// <summary>
        /// Create a directory object with a shadow
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create the directory with</param>
        /// <param name="desired_access">The desired access to the directory</param>
        /// <param name="shadow_dir">The shadow directory</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        /// <exception cref="NtException">Thrown on error and throw_on_error is true.</exception>
        public static NtResult<NtDirectory> Create(ObjectAttributes obj_attributes, DirectoryAccessRights desired_access, 
            NtDirectory shadow_dir, bool throw_on_error)
        {
            return Create(obj_attributes, desired_access, shadow_dir, DirectoryCreateFlags.None, throw_on_error);
        }

        /// <summary>
        /// Create a directory object with a shadow
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create the directory with</param>
        /// <param name="desired_access">The desired access to the directory</param>
        /// <param name="shadow_dir">The shadow directory</param>
        /// <param name="flags">Flags for creation.</param>
        /// <returns>The directory object</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public static NtDirectory Create(ObjectAttributes obj_attributes, DirectoryAccessRights desired_access, 
            NtDirectory shadow_dir, DirectoryCreateFlags flags)
        {
            return Create(obj_attributes, desired_access, shadow_dir, flags, true).Result;
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
            return Create(obj_attributes, desired_access, shadow_dir, DirectoryCreateFlags.None, true).Result;
        }

        /// <summary>
        /// Create a directory object
        /// </summary>
        /// <param name="name">The directory object to create, if null will create a unnamed directory object</param>
        /// <param name="desired_access">The desired access to the directory</param>
        /// <param name="root">Root directory from where to start the creation operation</param>
        /// <returns>The directory object</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public static NtDirectory Create(string name, NtObject root, 
            DirectoryAccessRights desired_access)
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
        public static NtDirectory Create(string name, NtObject root, 
            DirectoryAccessRights desired_access, NtDirectory shadow_dir)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, desired_access, shadow_dir);
            }
        }

        /// <summary>
        /// Create a directory object 
        /// </summary>
        /// <param name="name">The directory object to create, if null will create a unnamed directory object</param>
        /// <returns>The directory object</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public static NtDirectory Create(string name)
        {
            return Create(name, null, DirectoryAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Open a session directory.
        /// </summary>
        /// <param name="sessionid">The session ID to open</param>
        /// <param name="sub_directory">Sub directory to open.</param>
        /// <param name="desired_access">Desired access to open directory.</param>
        /// <returns>The directory object</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public static NtDirectory OpenSessionDirectory(int sessionid, string sub_directory, DirectoryAccessRights desired_access)
        {
            string directory = $@"\Sessions\{sessionid}";
            if (!string.IsNullOrEmpty(sub_directory))
            {
                directory = $@"{directory}\{sub_directory}";
            }
            return Open(directory, null, desired_access);
        }

        /// <summary>
        /// Open the current session directory.
        /// </summary>
        /// <returns>The directory object</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public static NtDirectory OpenSessionDirectory(string sub_directory)
        {
            return OpenSessionDirectory(NtProcess.Current.SessionId, sub_directory, DirectoryAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Open the current session directory.
        /// </summary>
        /// <returns>The directory object</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public static NtDirectory OpenSessionDirectory()
        {
            return OpenSessionDirectory(null);
        }

        /// <summary>
        /// Open basenamedobjects for a session.
        /// </summary>
        /// <param name="sessionid">The session ID to open</param>
        /// <returns>The directory object</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public static NtDirectory OpenBaseNamedObjects(int sessionid)
        {
            return Open(GetBasedNamedObjects(sessionid));
        }

        /// <summary>
        /// Open basenamedobjects for current session.
        /// </summary>
        /// <returns>The directory object</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public static NtDirectory OpenBaseNamedObjects()
        {
            return OpenBaseNamedObjects(NtProcess.Current.SessionId);
        }

        /// <summary>
        /// Get the based named object's directory for a session.
        /// </summary>
        /// <param name="session_id">The session ID</param>
        /// <returns>The based named object's directory.</returns>
        public static string GetBasedNamedObjects(int session_id)
        {
            if (session_id == 0)
            {
                return @"\BaseNamedObjects";
            }
            else
            {
                return $@"\Sessions\{session_id}\BaseNamedObjects";
            }
        }

        /// <summary>
        /// Get the based named object's directory for the current session.
        /// </summary>
        /// <returns>The based named object's directory.</returns>
        public static string GetBasedNamedObjects()
        {
            return GetBasedNamedObjects(NtProcess.Current.SessionId);
        }

        /// <summary>
        /// Get the a session's Windows object directory.
        /// </summary>
        /// <param name="session_id">The session id to use.</param>
        /// <returns>The path to the windows object directory.</returns>
        public static string GetWindows(int session_id)
        {
            if (session_id == 0)
            {
                return @"\Windows";
            }
            else
            {
                return $@"\Sessions\{session_id}\Windows";
            }
        }

        /// <summary>
        /// Get the current session's Windows object directory.
        /// </summary>
        /// <returns>The path to the windows object directory.</returns>
        public static string GetWindows()
        {
            return GetWindows(NtProcess.Current.SessionId);
        }

        /// <summary>
        /// Get the a session's Window Stations object directory.
        /// </summary>
        /// <param name="session_id">The session id to use.</param>
        /// <returns>The path to the window stations object directory.</returns>
        public static string GetWindowStations(int session_id)
        {
            return $@"{GetWindows(session_id)}\WindowStations";
        }

        /// <summary>
        /// Get the current session's Window Stations object directory.
        /// </summary>
        /// <returns>The path to the window stations object directory.</returns>
        public static string GetWindowStations()
        {
            return GetWindowStations(NtProcess.Current.SessionId);
        }

        /// <summary>
        /// Open dos devices directory for a token.
        /// </summary>
        /// <returns>The directory object</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public static NtDirectory OpenDosDevicesDirectory(NtToken token)
        {
            Luid authid = token.AuthenticationId;
            if (authid.Equals(NtToken.LocalSystemAuthId))
            {
                return Open(@"\GLOBAL??");
            }

            return Open($@"\Sessions\0\DosDevices\{authid}");
        }

        /// <summary>
        /// Open dos devices directory for current effective token.
        /// </summary>
        /// <returns>The directory object</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public static NtDirectory OpenDosDevicesDirectory()
        {
            using (NtToken token = NtToken.OpenEffectiveToken())
            {
                return OpenDosDevicesDirectory(token);
            }
        }

        /// <summary>
        /// Create a private namespace directory.
        /// </summary>
        /// <param name="obj_attributes">Object attributes for the directory</param>
        /// <param name="boundary_descriptor">Boundary descriptor for the namespace</param>
        /// <param name="desired_access">Desired access for the directory</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The directory object</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public static NtResult<NtDirectory> CreatePrivateNamespace(ObjectAttributes obj_attributes, 
            BoundaryDescriptor boundary_descriptor, DirectoryAccessRights desired_access, bool throw_on_error)
        {
            return NtSystemCalls.NtCreatePrivateNamespace(out SafeKernelObjectHandle handle, desired_access, 
                obj_attributes, boundary_descriptor.Handle).CreateResult(throw_on_error, () => new NtDirectory(handle, true));
        }

        /// <summary>
        /// Create a private namespace directory.
        /// </summary>
        /// <param name="obj_attributes">Object attributes for the directory</param>
        /// <param name="boundary_descriptor">Boundary descriptor for the namespace</param>
        /// <param name="desired_access">Desired access for the directory</param>
        /// <returns>The directory object</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public static NtDirectory CreatePrivateNamespace(ObjectAttributes obj_attributes, BoundaryDescriptor boundary_descriptor, DirectoryAccessRights desired_access)
        {
            return CreatePrivateNamespace(obj_attributes, boundary_descriptor, desired_access, true).Result;
        }

        /// <summary>
        /// Create a private namespace directory.
        /// </summary>
        /// <param name="boundary_descriptor">Boundary descriptor for the namespace</param>
        /// <returns>The directory object</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public static NtDirectory CreatePrivateNamespace(BoundaryDescriptor boundary_descriptor)
        {
            using (ObjectAttributes obja = new ObjectAttributes())
            {
                return CreatePrivateNamespace(obja, boundary_descriptor, DirectoryAccessRights.MaximumAllowed);
            }
        }

        /// <summary>
        /// Open a private namespace directory.
        /// </summary>
        /// <param name="obj_attributes">Object attributes for the directory</param>
        /// <param name="boundary_descriptor">Boundary descriptor for the namespace</param>
        /// <param name="desired_access">Desired access for the directory</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The directory object</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public static NtResult<NtDirectory> OpenPrivateNamespace(ObjectAttributes obj_attributes, 
            BoundaryDescriptor boundary_descriptor, DirectoryAccessRights desired_access, bool throw_on_error)
        {
            return NtSystemCalls.NtOpenPrivateNamespace(out SafeKernelObjectHandle handle, desired_access, obj_attributes, boundary_descriptor.Handle)
                .CreateResult(throw_on_error, () => new NtDirectory(handle, true));
        }

        /// <summary>
        /// Open a private namespace directory.
        /// </summary>
        /// <param name="obj_attributes">Object attributes for the directory</param>
        /// <param name="boundary_descriptor">Boundary descriptor for the namespace</param>
        /// <param name="desired_access">Desired access for the directory</param>
        /// <returns>The directory object</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public static NtDirectory OpenPrivateNamespace(ObjectAttributes obj_attributes, BoundaryDescriptor boundary_descriptor, DirectoryAccessRights desired_access)
        {
            return OpenPrivateNamespace(obj_attributes, boundary_descriptor, desired_access, true).Result;
        }

        /// <summary>
        /// Open a private namespace directory.
        /// </summary>
        /// <param name="boundary_descriptor">Boundary descriptor for the namespace</param>
        /// <returns>The directory object</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public static NtDirectory OpenPrivateNamespace(BoundaryDescriptor boundary_descriptor)
        {
            using (ObjectAttributes obja = new ObjectAttributes())
            {
                return OpenPrivateNamespace(obja, boundary_descriptor, DirectoryAccessRights.MaximumAllowed);
            }
        }

        /// <summary>
        /// Returns whether a directory exists for this path.
        /// </summary>
        /// <param name="path">The path to the entry.</param>
        /// <param name="root">The root directory.</param>
        /// <returns>True if the directory exists for the specified path.</returns>
        public static bool DirectoryExists(string path, NtDirectory root)
        {
            using (var dir = Open(path, root, DirectoryAccessRights.MaximumAllowed, false))
            {
                return dir.IsSuccess;
            }
        }

        /// <summary>
        /// Get the type of a directory entry by path.
        /// </summary>
        /// <param name="path">The path to the directory entry</param>
        /// <param name="root">The root object to look up if path is relative</param>
        /// <returns>The type name, or null if it can't be found.</returns>
        public static string GetDirectoryEntryType(string path, NtObject root)
        {
            if (root == null && path == @"\")
            {
                return "Directory";
            }

            string dir_name = GetDirectoryName(path);
            if (dir_name == string.Empty && root == null)
            {
                dir_name = @"\";
            }
            using (var dir = Open(dir_name, root, DirectoryAccessRights.Query, false))
            {
                if (dir.IsSuccess)
                {
                    ObjectDirectoryInformation dir_info = dir.Result.GetDirectoryEntry(GetFileName(path));
                    if (dir_info != null)
                    {
                        return dir_info.NtTypeName;
                    }
                }
            }

            return null;
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Query the directory for a list of entries.
        /// </summary>
        /// <returns>The list of entries.</returns>
        /// <exception cref="NtException">Thrown on error</exception>
        public IEnumerable<ObjectDirectoryInformation> Query()
        {
            string base_path = FullPath.TrimEnd('\\');
            using (SafeStructureInOutBuffer<OBJECT_DIRECTORY_INFORMATION> buffer
                = new SafeStructureInOutBuffer<OBJECT_DIRECTORY_INFORMATION>(2048, true))
            {
                NtStatus status;
                int context = 0;
                int return_length = 0;
                while ((status = NtSystemCalls.NtQueryDirectoryObject(Handle, buffer, buffer.Length, false,
                    true, ref context, out return_length)) == NtStatus.STATUS_MORE_ENTRIES)
                {
                    buffer.Resize(buffer.Length * 2);
                }

                if (status == NtStatus.STATUS_NO_MORE_ENTRIES)
                {
                    yield break;
                }

                status.ToNtException();
                IntPtr current = buffer.DangerousGetHandle();
                while (true)
                {
                    OBJECT_DIRECTORY_INFORMATION dir_info = (OBJECT_DIRECTORY_INFORMATION)Marshal.PtrToStructure(current, typeof(OBJECT_DIRECTORY_INFORMATION));
                    string name = dir_info.Name.ToString();
                    if (name.Length == 0)
                    {
                        break;
                    }
                    yield return new ObjectDirectoryInformation(this, base_path, dir_info);
                    current += Marshal.SizeOf(dir_info);
                }
            }
        }

        /// <summary>
        /// Visit all accessible directories under this one.
        /// </summary>
        /// <param name="visitor">A function to be called on every accessible directory. Return true to continue enumeration.</param>
        /// <param name="desired_access">Specify the desired access for the directory</param>
        /// <param name="recurse">True to recurse into sub directories.</param>
        /// <param name="max_depth">Specify max recursive depth. -1 to not set a limit.</param>
        /// <returns>True if all children were visited.</returns>
        public bool VisitAccessibleDirectories(Func<NtDirectory, bool> visitor, DirectoryAccessRights desired_access, bool recurse, int max_depth)
        {
            if (max_depth == 0)
            {
                return true;
            }

            using (var for_query = Duplicate(DirectoryAccessRights.Query, AttributeFlags.None, DuplicateObjectOptions.SameAttributes, false))
            {
                if (!for_query.IsSuccess)
                {
                    return true;
                }

                ObjectDirectoryInformation[] entries = for_query.Result.Query().Where(e => e.IsDirectory).ToArray();
                if (max_depth > 0)
                {
                    max_depth--;
                }

                foreach (var entry in entries)
                {
                    using (var obj_attr = new ObjectAttributes(entry.Name, AttributeFlags.CaseInsensitive, this))
                    {
                        using (var directory = NtDirectory.Open(obj_attr, desired_access, false))
                        {
                            if (!directory.IsSuccess)
                            {
                                continue;
                            }

                            if (!visitor(directory.Result))
                            {
                                return false;
                            }

                            if (recurse)
                            {
                                if (!directory.Result.VisitAccessibleDirectories(visitor, desired_access, recurse, max_depth))
                                {
                                    return false;
                                }
                            }
                        }
                    }
                }
            }

            return true;
        }

        /// <summary>
        /// Visit all accessible directories under this one.
        /// </summary>
        /// <param name="visitor">A function to be called on every accessible directory. Return true to continue enumeration.</param>
        public void VisitAccessibleDirectories(Func<NtDirectory, bool> visitor)
        {
            VisitAccessibleDirectories(visitor, false);
        }

        /// <summary>
        /// Visit all accessible directories under this one.
        /// </summary>
        /// <param name="visitor">A function to be called on every accessible directory. Return true to continue enumeration.</param>
        /// <param name="recurse">True to recurse into sub directories.</param>
        public void VisitAccessibleDirectories(Func<NtDirectory, bool> visitor, bool recurse)
        {
            VisitAccessibleDirectories(visitor, DirectoryAccessRights.MaximumAllowed, recurse);
        }

        /// <summary>
        /// Visit all accessible directories under this one.
        /// </summary>
        /// <param name="visitor">A function to be called on every accessible directory. Return true to continue enumeration.</param>
        /// <param name="desired_access">Specify the desired access for the directory</param>
        /// <param name="recurse">True to recurse into sub directories.</param>
        public void VisitAccessibleDirectories(Func<NtDirectory, bool> visitor, DirectoryAccessRights desired_access, bool recurse)
        {
            VisitAccessibleDirectories(visitor, desired_access, recurse, -1);
        }

        /// <summary>
        /// Deletes a private namespace. If not a private namespace this does nothing.
        /// </summary>
        public void Delete()
        {
            if (_private_namespace)
            {
                NtSystemCalls.NtDeletePrivateNamespace(Handle).ToNtException();
            }
        }

        /// <summary>
        /// Get a directory entry based on a name.
        /// </summary>
        /// <param name="name">The name of the entry.</param>
        /// <param name="typename">The typename to verify against, can be null.</param>
        /// <param name="case_sensitive">True if look up is case sensitive.</param>
        /// <returns>The directory entry, or null if it can't be found.</returns>
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

        /// <summary>
        /// Get a directory entry based on a name.
        /// </summary>
        /// <param name="name">The name of the entry.</param>
        /// <returns>The directory entry, or null if it can't be found.</returns>
        public ObjectDirectoryInformation GetDirectoryEntry(string name)
        {
            return GetDirectoryEntry(name, null, false);
        }

        /// <summary>
        /// Check whether a directory is exists relative to the current directory.
        /// </summary>
        /// <param name="relative_path">Relative path to directory</param>
        /// <returns>True if the directory exists.</returns>
        public bool DirectoryExists(string relative_path)
        {
            return DirectoryExists(relative_path, this);
        }

        /// <summary>
        /// Set the session ID for this directory to the current session.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <remarks>Needs SeTcbPrivilege.</remarks>
        public NtStatus SetCurrentSessionId(bool throw_on_error = true)
        {
            return NtSystemCalls.NtSetInformationObject(Handle, 
                ObjectInformationClass.ObjectSessionInformation, 
                SafeHGlobalBuffer.Null, 0).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Set the session object for this directory to the current session.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        /// <remarks>Needs SeTcbPrivilege.</remarks>
        public NtStatus SetCurrentSessionObject(bool throw_on_error = true)
        {
            return NtSystemCalls.NtSetInformationObject(Handle,
                ObjectInformationClass.ObjectSessionObjectInformation,
                SafeHGlobalBuffer.Null, 0).ToNtException(throw_on_error);
        }

        #endregion

        #region Public Properties
        /// <summary>
        /// Returns whether this object is a container.
        /// </summary>
        public override bool IsContainer => true;
        #endregion

        #region Private Members

        private bool _private_namespace;

        private static string GetDirectoryName(string path)
        {
            int index = path.LastIndexOf('\\');
            if (index < 0)
            {
                return string.Empty;
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

        #endregion
    }
}
