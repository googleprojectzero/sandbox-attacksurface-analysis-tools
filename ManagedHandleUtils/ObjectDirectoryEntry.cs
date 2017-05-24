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
using System;

namespace SandboxAnalysisUtils
{
    public class ObjectDirectoryEntry : IComparable<ObjectDirectoryEntry>
    {
        string _name;
        string _type_name;
        ObjectDirectory _directory;
        string _sddl;
        byte[] _sd;

        void ReadSecurityDescriptor()
        {
            try
            {
                if (NtObject.CanOpenType(_type_name))
                {
                    using (NtObject obj = NtObject.OpenWithType(_type_name, _name, _directory.Directory, GenericAccessRights.ReadControl))
                    {
                        _sd = obj.GetSecurityDescriptorBytes(SecurityInformation.Owner | SecurityInformation.Group | SecurityInformation.Dacl | SecurityInformation.Label);
                    }
                }
            }
            catch
            {
                _sd = new byte[0];
            }
        }

        void ReadStringSecurityDescriptor()
        {
            if (_sd == null)
            {
                ReadSecurityDescriptor();
            }

            if (_sd.Length > 0)
            {
                _sddl = NtSecurity.SecurityDescriptorToSddl(_sd, SecurityInformation.Owner | SecurityInformation.Group | SecurityInformation.Dacl | SecurityInformation.Label);
            }
            else
            {
                _sddl = string.Empty;
            }

        }

        internal ObjectDirectoryEntry(string name, string type_name, ObjectDirectory directory)
        {
            _name = name;
            _type_name = type_name;
            _directory = directory;
        }

        public string ObjectName
        {
            get
            {
                return _name;
            }
        }

        public string TypeName
        {
            get
            {
                return _type_name;
            }
        }

        public bool IsDirectory
        {
            get
            {
                return _type_name.Equals("Directory", StringComparison.OrdinalIgnoreCase);
            }
        }

        public bool IsSymlink
        {
            get
            {
                return _type_name.Equals("SymbolicLink", StringComparison.OrdinalIgnoreCase);
            }
        }

        public ObjectDirectory ParentDirectory
        {
            get
            {
                return _directory;
            }
        }

        public string FullPath
        {
            get
            {
                String base_name = _directory.FullPath.TrimEnd(new char[] { '\\' });

                return String.Format("{0}\\{1}", base_name, _name);
            }
        }

        public byte[] SecurityDescriptor
        {
            get
            {
                if (_sd == null)
                {
                    ReadSecurityDescriptor();
                }

                return _sd;
            }
        }

        public string StringSecurityDescriptor
        {
            get
            {
                if (_sddl == null)
                {
                    ReadStringSecurityDescriptor();
                }

                return _sddl;
            }
        }

        public override int GetHashCode()
        {
            return _name.GetHashCode() ^ _type_name.GetHashCode();
        }

        public override bool Equals(Object other)
        {
            if (other is ObjectDirectoryEntry)
            {
                ObjectDirectoryEntry other_entry = (ObjectDirectoryEntry)other;
                return _name.Equals(other_entry._name) && _type_name.Equals(other_entry._type_name);
            }
            else
            {
                return false;
            }
        }

        public int CompareTo(ObjectDirectoryEntry other)

        {
            int ret = _name.CompareTo(other._name);
            if (ret == 0)
            {
                ret = _type_name.CompareTo(other._type_name);
            }

            return ret;
        }
    }
}
