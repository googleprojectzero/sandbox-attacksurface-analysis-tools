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
using System.Collections.Generic;
using System.Linq;

namespace SandboxAnalysisUtils
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
            DirectoryAccessRights granted_access = _directory.GrantedAccess;
            if ((granted_access & DirectoryAccessRights.ReadControl) == DirectoryAccessRights.ReadControl)
            {
                _sd = _directory.GetSecurityDescriptorBytes(SecurityInformation.Dacl | SecurityInformation.Label | SecurityInformation.Group | SecurityInformation.Owner);
                _sddl = NtSecurity.SecurityDescriptorToSddl(_sd, SecurityInformation.Dacl | SecurityInformation.Label | SecurityInformation.Group | SecurityInformation.Owner);
            }
            else
            {
                _sd = new byte[0];
                _sddl = String.Empty;
            }


            _full_path = _directory.FullPath;
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
            return NtDirectory.Open(path, root != null ? root._directory : null, DirectoryAccessRights.MaximumAllowed);
        }

        private static NtDirectory OpenNamespace(string path)
        {
            using (BoundaryDescriptor boundary = BoundaryDescriptor.CreateFromString(path))
            {
                return NtDirectory.OpenPrivateNamespace(boundary);
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
