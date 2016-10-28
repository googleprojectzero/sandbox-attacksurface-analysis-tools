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

using NtApiDotNet;

namespace SandboxPowerShellApi
{
    public class ObjectDirectoryEntry
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
                                _sd = obj.GetSecurityDescriptor();
                            }

                            NtSymbolicLink link = obj as NtSymbolicLink;
                            if (link != null && link.IsAccessGranted(SymbolicLinkAccessRights.Query))
                            {
                                _symlink_target = link.Query();
                            }

                            _maximum_granted_access = obj.GetGrantedAccessObject();
                        }
                    }
                    catch
                    {
                    }
                }
            }
        }

        public string Name { get; private set; }
        public string TypeName { get; private set; }
        public bool IsDirectory { get; private set; }
        public bool IsSymbolicLink { get; private set; }
        public string RelativePath { get; private set; }
        public SecurityDescriptor SecurityDescriptor
        {
            get
            {
                PopulateData();
                return _sd;
            }
        }

        public string SymbolicLinkTarget
        {
            get
            {
                PopulateData();
                return _symlink_target;
            }
        }

        public object MaximumGrantedAccess
        {
            get
            {
                PopulateData();
                return _maximum_granted_access;
            }
        }


        public NtObject ToObject()
        {
            return NtObject.OpenWithType(TypeName, RelativePath, _base_directory, GenericAccessRights.MaximumAllowed);
        }

        internal ObjectDirectoryEntry(NtDirectory base_directory, string relative_path, string name, string typename)
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
