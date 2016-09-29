using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.Linq;

namespace HandleUtils
{
    public sealed class ObjectDirectory : IDisposable
    {
        private string _orig_path;
        private string _full_path;
        private List<ObjectDirectoryEntry> _entries;
        private string _sddl;
        private byte[] _sd;
        private NtDirectory _directory;

        private void PopulateEntries()
        {
            DirectoryAccessRights granted_access = _directory.GetGrantedAccess();
            if ((granted_access & DirectoryAccessRights.ReadControl) == DirectoryAccessRights.ReadControl)
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

            if ((granted_access & DirectoryAccessRights.Query) != DirectoryAccessRights.Query)
            {
                _entries = new List<ObjectDirectoryEntry>();
            }
            else
            {
                _entries = new List<ObjectDirectoryEntry>(_directory.Query().Select(e => new ObjectDirectoryEntry(e.Name, e.TypeName, this)));
            }
        }

        public ObjectDirectory Duplicate()
        {
            ObjectDirectory ret = new ObjectDirectory();
            ret._sddl = _sddl;
            ret._sd = (byte[])_sd.Clone();
            ret._orig_path = _orig_path;
            ret._full_path = _full_path;
            ret._entries = new List<ObjectDirectoryEntry>(_entries.Select(e => new ObjectDirectoryEntry(e.ObjectName, e.TypeName, ret)));
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

        public ObjectDirectory ParentDirectory
        {
            get
            {
                int index = _full_path.LastIndexOf("\\");
                if (index > 0)
                {
                    return new ObjectDirectory(null, _full_path.Substring(0, index));
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

        public IEnumerable<ObjectDirectoryEntry> Entries
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
        

        public NtDirectory Directory
        {
            get { return _directory; }
        }

        private static NtDirectory OpenPath(ObjectDirectory root, string path)
        {
            try
            {
                return NtDirectory.Open(path, root != null ? root._directory : null, DirectoryAccessRights.MaximumAllowed);
            }
            catch (NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        private static NtDirectory OpenNamespace(string path)
        {
            string[] parts = path.Split(new char[] { '@' }, 2);
            string obj_name = parts.Length > 1 ? parts[1] : parts[0];

            try
            {
                BoundaryDescriptor boundary = new BoundaryDescriptor(obj_name);

                if (parts.Length > 1)
                {
                    boundary.AddSids(parts[0].Split(':').Select(s => new Sid(s)));
                }

                return NtDirectory.OpenPrivateNamespace(boundary);
            }
            catch (NtException ex)
            {
                throw ex.AsWin32Exception();
            }
        }

        internal ObjectDirectory(ObjectDirectory root, string object_path)
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

        private ObjectDirectory()
        { }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        private void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (_directory != null)
                {
                    _directory.Close();
                    _directory = null;
                }
                disposedValue = true;
            }
        }

        ~ObjectDirectory()
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
