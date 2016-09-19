using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.Linq;

namespace HandleUtils
{
    public sealed class ObjectDirectoryX : IDisposable
    {
        private string _orig_path;
        private string _full_path;
        private List<ObjectDirectoryEntryX> _entries;
        private string _sddl;
        private byte[] _sd;
        private NtDirectory _directory;
        private NativeHandle _handle;

        private void PopulateEntries()
        {
            DirectoryObjectAccessRights granted_access = _directory.GetGrantedAccess();
            if ((granted_access & DirectoryObjectAccessRights.ReadControl) == DirectoryObjectAccessRights.ReadControl)
            {
                _sd = _directory.GetRawSecurityDescriptor(SecurityInformation.Dacl | SecurityInformation.Label | SecurityInformation.Group | SecurityInformation.Owner);
                _sddl = NtSecurity.SecurityDescriptorToSddl(_sd, SecurityInformation.Dacl | SecurityInformation.Label | SecurityInformation.Group | SecurityInformation.Owner);
            }
            else
            {
                _sd = new byte[0];
                _sddl = String.Empty;
            }


            _full_path = _directory.GetName();
            if (String.IsNullOrWhiteSpace(_full_path))
            {
                _full_path = _orig_path;
            }

            if ((granted_access & DirectoryObjectAccessRights.Query) != DirectoryObjectAccessRights.Query)
                return;

            _entries = new List<ObjectDirectoryEntryX>(_directory.Query().Select(e => new ObjectDirectoryEntryX(e.Name, e.TypeName, this)));
        }

        public ObjectDirectoryX Duplicate()
        {
            ObjectDirectoryX ret = new ObjectDirectoryX();
            ret._sddl = _sddl;
            ret._sd = (byte[])_sd.Clone();
            ret._orig_path = _orig_path;
            ret._full_path = _full_path;
            ret._entries = new List<ObjectDirectoryEntryX>(_entries.Select(e => new ObjectDirectoryEntryX(e.ObjectName, e.TypeName, ret)));
            ret._directory = _directory.Duplicate();
            return ret;
        }

        public void Refresh()
        {
            PopulateEntries();
        }

        public string FullPath
        {
            get
            {
                return _full_path;
            }
        }

        public string OriginalPath
        {
            get
            {
                return _orig_path;
            }
        }

        public byte[] SecurityDescriptor
        {
            get
            {
                return (byte[])_sd.Clone();
            }
        }

        public string StringSecurityDescriptor
        {
            get
            {
                return _sddl;
            }
        }

        public ObjectDirectoryX ParentDirectory
        {
            get
            {
                int index = _full_path.LastIndexOf("\\");
                if (index > 0)
                {
                    return new ObjectDirectoryX(null, _full_path.Substring(0, index));
                }
                else
                {
                    return null;
                }
            }
        }

        public string Name
        {
            get
            {
                int index = _full_path.LastIndexOf("\\");
                if (index > 0)
                {
                    return _full_path.Substring(index + 1);
                }
                else
                {
                    return _full_path;
                }
            }
        }

        public IEnumerable<ObjectDirectoryEntryX> Entries
        {
            get
            {
                if (_entries == null)
                {
                    PopulateEntries();
                }
                return _entries.AsReadOnly();
            }
        }

        public void EditSecurity(IntPtr hwnd, bool writeable)
        {
        }

        public NativeHandle Handle
        {
            get
            {
                return new NativeHandle(_directory.Handle.DangerousGetHandle());
            }
        }

        internal NtDirectory Directory
        {
            get { return _directory; }
        }

        private static NtDirectory OpenPath(ObjectDirectoryX root, string path)
        {
            return NtDirectory.Open(path, root._directory, DirectoryObjectAccessRights.MaximumAllowed);
        }

        private static NtDirectory OpenNamespace(string path)
        {
            string[] parts = path.Split(new char[] { '@' }, 2);
            string obj_name = parts.Length > 1 ? parts[1] : parts[0];

            BoundaryDescriptor boundary = new BoundaryDescriptor(obj_name);

            if (parts.Length > 1)
            {
                boundary.AddSids(parts[0].Split(':').Select(s => new Sid(s)));
            }

            return NtDirectory.OpenPrivateNamespace(boundary);
        }


        public ObjectDirectoryX(ObjectDirectoryX root, string object_path)
        {
            _orig_path = object_path;

            if (_orig_path.StartsWith("\\") || root != null)
            {
                _directory = OpenPath(root, _orig_path);
            }
            else
            {
                _directory = OpenNamespace(_orig_path);
            }

            PopulateEntries();
        }

        private ObjectDirectoryX()
        { }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        private void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                _directory.Close();
                disposedValue = true;
            }
        }

        ~ObjectDirectoryX()
        {
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
}
