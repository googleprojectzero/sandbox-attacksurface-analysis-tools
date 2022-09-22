//  Copyright 2022 Google LLC. All Rights Reserved.
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

namespace NtApiDotNet.Net.Smb2
{
    /// <summary>
    /// Class to represent a connected SMB2 share.
    /// </summary>
    public sealed class Smb2Share : IDisposable
    {
        #region Private Members
        private readonly Smb2Session _session;
        private readonly uint _tree_id;
        private bool _disconnected;
        #endregion

        #region Public Properties
        /// <summary>
        /// The share tree path.
        /// </summary>
        public string Path { get; }

        /// <summary>
        /// The type of share.
        /// </summary>
        public Smb2ShareType ShareType { get; }

        /// <summary>
        /// The flags for the share.
        /// </summary>
        public Smb2ShareFlags Flags { get; }

        /// <summary>
        /// The capabilities for the share.
        /// </summary>
        public Smb2ShareCapabilities Capabilities { get; }

        /// <summary>
        /// The maximal access for the share.
        /// </summary>
        public FileAccessRights MaximalAccess { get; }
        #endregion

        #region Internal Members
        internal Smb2Client Client => _session.Client;

        internal Smb2Share(Smb2Session session, string path, uint tree_id, Smb2ShareType share_type, Smb2ShareFlags flags, 
            Smb2ShareCapabilities caps, FileAccessRights maximal_access)
        {
            _session = session;
            _tree_id = tree_id;
            Path = path;
            ShareType = share_type;
            Flags = flags;
            Capabilities = caps;
            MaximalAccess = maximal_access;
        }

        internal Smb2CommandResult<T> ExchangeCommand<T>(Smb2RequestPacket packet) where T : Smb2ResponsePacket, new()
        {
            if (_disconnected)
                throw new InvalidOperationException("Share is disconnected.");

            return _session.ExchangeCommand<T>(packet, _tree_id);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Create a file in the share.
        /// </summary>
        /// <param name="name">The name relative to the share.</param>
        /// <param name="create_disposition">Create disposition.</param>
        /// <param name="desired_access">Desired access for the file.</param>
        /// <param name="share_access">Share access for the file.</param>
        /// <param name="file_attributes">Attributes for the file.</param>
        /// <param name="create_options">Create options for the file.</param>
        /// <param name="impersonation_level">Impersonation level for the file.</param>
        /// <param name="requested_oplock_level">Request oplock level.</param>
        /// <returns>Returns a reference to the SMB2 file.</returns>
        public Smb2File Create(string name, FileDisposition create_disposition, 
            FileAccessRights desired_access = FileAccessRights.MaximumAllowed,
            FileShareMode share_access = FileShareMode.None, 
            FileAttributes file_attributes = FileAttributes.Normal, 
            FileOpenOptions create_options = FileOpenOptions.None, 
            SecurityImpersonationLevel impersonation_level = SecurityImpersonationLevel.Impersonation, 
            Smb2OplockLevel requested_oplock_level = Smb2OplockLevel.None)
        {
            if (name is null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            Smb2CreateRequestPacket request = new Smb2CreateRequestPacket
            {
                Name = name,
                CreateDisposition = create_disposition,
                DesiredAccess = desired_access,
                ShareAccess = share_access,
                FileAttributes = file_attributes,
                CreateOptions = create_options,
                ImpersonationLevel = impersonation_level,
                RequestedOplockLevel = requested_oplock_level
            };

            var reply = ExchangeCommand<Smb2CreateResponsePacket>(request);
            return new Smb2File(this, name, reply.Response);
        }

        /// <summary>
        /// Open a file in the share.
        /// </summary>
        /// <param name="name">The name relative to the share.</param>
        /// <param name="desired_access">Desired access for the file.</param>
        /// <param name="share_access">Share access for the file.</param>
        /// <param name="open_options">Open options for the file.</param>
        /// <param name="impersonation_level">Impersonation level for the file.</param>
        /// <param name="requested_oplock_level">Request oplock level.</param>
        /// <returns></returns>
        public Smb2File Open(string name, FileAccessRights desired_access = FileAccessRights.MaximumAllowed,
            FileShareMode share_access = FileShareMode.None,
            FileOpenOptions open_options = FileOpenOptions.None,
            SecurityImpersonationLevel impersonation_level = SecurityImpersonationLevel.Impersonation,
            Smb2OplockLevel requested_oplock_level = Smb2OplockLevel.None)
        {
            return Create(name, FileDisposition.Open, desired_access, share_access, FileAttributes.Normal, 
                open_options, impersonation_level, requested_oplock_level);
        }

        /// <summary>
        /// Disconnect the share.
        /// </summary>
        public void Disconnect()
        {
            if (_disconnected)
                return;
            try
            {
                ExchangeCommand<Smb2IgnoredResponsePacket>(new Smb2TreeDisconnectRequestPacket());
            }
            finally
            {
                _disconnected = true;
            }
        }
        #endregion

        #region IDisposable Implementation
        void IDisposable.Dispose()
        {
            try
            {
                Disconnect();
            }
            catch
            {
            }
        }
        #endregion
    }
}
