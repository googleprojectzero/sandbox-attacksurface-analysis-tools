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
        private string _full_path;

        public string Name { get; private set; }
        public string TypeName { get; private set; }
        public bool IsDirectory { get; private set; }
        public SecurityDescriptor SecurityDescriptor { get; private set; }

        private static SecurityDescriptor GetObjectSecurityDescriptor(ObjectDirectoryInformation dir_info)
        {
            try
            {
                using (NtObject obj = dir_info.Open(GenericAccessRights.ReadControl))
                {
                    return obj.GetSecurityDescriptor();
                }
            }
            catch
            {
            }

            return new SecurityDescriptor();
        }

        public NtObject ToObject()
        {
            return NtObject.OpenWithType(TypeName, _full_path, _base_directory, GenericAccessRights.MaximumAllowed);
        }

        internal ObjectDirectoryEntry(NtDirectory base_directory, string fullpath, string name, string typename, bool is_directory, SecurityDescriptor sd)
        {
            Name = name;
            TypeName = typename;
            IsDirectory = is_directory;
            SecurityDescriptor = sd ?? new SecurityDescriptor();
            _full_path = fullpath;
            _base_directory = base_directory;
        }

        internal ObjectDirectoryEntry(NtDirectory base_directory, string fullpath, ObjectDirectoryInformation dir_info) 
            : this(base_directory, fullpath, dir_info.Name, dir_info.TypeName, dir_info.IsDirectory, GetObjectSecurityDescriptor(dir_info))
        {
        }
    }
}
