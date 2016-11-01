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

using NtApiDotNet;

namespace NtObjectManager
{
    /// <summary>
    /// A class representing a NT object manager directory entry.
    /// </summary>
    public class NtDirectoryEntry
    {
        private NtDirectory _base_directory;
        private SecurityDescriptor _sd;
        private string _symlink_target;
        private object _maximum_granted_access;
        private bool _data_populated;

        private void PopulateData()
        {
            if (!_data_populated)
            {
                _data_populated = true;
                if (NtObject.CanOpenType(TypeName))
                {
                    try
                    {
                        using (NtObject obj = ToObject())
                        {
                            if (obj.IsAccessGrantedRaw(GenericAccessRights.ReadControl))
                            {
                                _sd = obj.SecurityDescriptor;
                            }

                            NtSymbolicLink link = obj as NtSymbolicLink;
                            if (link != null && link.IsAccessGranted(SymbolicLinkAccessRights.Query))
                            {
                                _symlink_target = link.Target;
                            }

                            _maximum_granted_access = obj.GrantedAccessObject;
                        }
                    }
                    catch
                    {
                    }
                }
            }
        }

        /// <summary>
        /// Get the name of the entry.
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Get the NT type name of the entry.
        /// </summary>
        public string TypeName { get; private set; }

        /// <summary>
        /// Indicates if this entry is a directory.
        /// </summary>
        public bool IsDirectory { get; private set; }

        /// <summary>
        /// Indicates if this entry is a symbolic link.
        /// </summary>
        public bool IsSymbolicLink { get; private set; }

        /// <summary>
        /// The relative path from the drive base to the entry.
        /// </summary>
        public string RelativePath { get; private set; }

        /// <summary>
        /// The security descriptor of the entry. This can be null if caller does not have permission to open the actual object.
        /// </summary>
        public SecurityDescriptor SecurityDescriptor
        {
            get
            {
                PopulateData();
                return _sd;
            }
        }

        /// <summary>
        /// The symbolic link target if IsSymbolicLink is true. Can be null if caller doesn't have permission to open the actual object.
        /// </summary>
        public string SymbolicLinkTarget
        {
            get
            {
                PopulateData();
                return _symlink_target;
            }
        }

        /// <summary>
        /// The maximum granted access to the entry. Can be set to 0 if the caller doesn't have permission to open the actual object.
        /// </summary>
        public object MaximumGrantedAccess
        {
            get
            {
                PopulateData();
                return _maximum_granted_access;
            }
        }

        /// <summary>
        /// Try and open the directory entry and return an actual NtObject handle.
        /// </summary>
        /// <returns>The object opened.</returns>
        /// <exception cref="NtException">Thrown if error opening object.</exception>
        /// <exception cref="System.ArgumentException">Thrown if invalid typename.</exception>
        public NtObject ToObject()
        {
            return NtObject.OpenWithType(TypeName, RelativePath, _base_directory, GenericAccessRights.MaximumAllowed);
        }

        internal NtDirectoryEntry(NtDirectory base_directory, string relative_path, string name, string typename)
        {
            Name = name;
            TypeName = typename;
            RelativePath = relative_path;
            _base_directory = base_directory;

            switch (typename.ToLower())
            {
                case "directory":
                case "key":
                    IsDirectory = true;
                    break;
                case "symboliclink":
                    IsSymbolicLink = true;
                    break;
            }

            _maximum_granted_access = 0;
        }
    }
}
