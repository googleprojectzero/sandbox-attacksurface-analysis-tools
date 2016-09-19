using NtApiDotNet;
using System;

namespace HandleUtils
{
    public class ObjectDirectoryEntryX : IComparable<ObjectDirectoryEntryX>
    {
        string _name;
        string _type_name;
        ObjectDirectoryX _directory;
        string _sddl;
        byte[] _sd;

        void ReadSecurityDescriptor()
        {
            try
            {
                using (NtObject obj = NtObject.OpenWithType(_type_name, _name, _directory.Directory, NtApiDotNet.GenericAccessRights.ReadControl))
                {
                    _sd = obj.GetRawSecurityDescriptor(SecurityInformation.Owner | SecurityInformation.Group | SecurityInformation.Dacl | SecurityInformation.Label);
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

        internal ObjectDirectoryEntryX(string name, string type_name, ObjectDirectoryX directory)
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

        public ObjectDirectoryX ParentDirectory
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
            if (other is ObjectDirectoryEntryX)
            {
                ObjectDirectoryEntryX other_entry = (ObjectDirectoryEntryX)other;
                return _name.Equals(other_entry._name) && _type_name.Equals(other_entry._type_name);
            }
            else
            {
                return false;
            }
        }

        public int CompareTo(ObjectDirectoryEntryX other)

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
