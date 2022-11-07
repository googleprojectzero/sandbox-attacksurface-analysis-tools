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
using System.Security.Cryptography;

namespace NtApiDotNet.Net.Smb2
{
    /// <summary>
    /// Class to represent a SMB2 session.
    /// </summary>
    public sealed class Smb2Session : IDisposable
    {
        #region Private Members
        private const int HASH_OFFSET = 48;
        private const int HASH_SIZE = 16;
        private readonly Smb2Client _client;
        private byte[] _full_session_key;
        private byte[] _session_key;
        private bool _logoff;

        private static void SetHash(byte[] data, byte[] hash)
        {
            Buffer.BlockCopy(hash, 0, data, HASH_OFFSET, HASH_SIZE);
        }
        #endregion

        #region Internal Members
        internal bool SigningEnabled => _full_session_key.Length > 0;
        internal ulong SessionId { get; }

        internal Smb2Client Client => _client;

        internal void SetSessionKey(byte[] session_key)
        {
            _full_session_key = session_key;
            _session_key = session_key;
            Array.Resize(ref _session_key, 16);
        }

        internal Smb2Session(Smb2Client client, ulong session_id)
        {
            _client = client;
            SessionId = session_id;
            _full_session_key = _session_key = Array.Empty<byte>();
        }
        internal void UpdateSignature(byte[] data)
        {
            if (!SigningEnabled)
                return;

            HMACSHA256 alg = new HMACSHA256(_session_key);
            SetHash(data, alg.ComputeHash(data));
        }

        internal bool CheckSignature(byte[] data)
        {
            if (!SigningEnabled)
                return true;

            byte[] to_hash = data.CloneBytes();
            SetHash(to_hash, new byte[HASH_SIZE]);
            HMACSHA256 alg = new HMACSHA256(_session_key);
            byte[] hash = new byte[HASH_SIZE];
            Buffer.BlockCopy(data, HASH_OFFSET, hash, 0, HASH_SIZE);
            return NtObjectUtils.EqualByteArray(hash, alg.ComputeHash(to_hash), HASH_SIZE);
        }

        internal Smb2CommandResult<T> ExchangeCommand<T>(Smb2RequestPacket packet, uint tree_id = 0) where T : Smb2ResponsePacket, new()
        {
            if (_logoff)
                throw new InvalidOperationException("Session logged off.");

            _client.CheckConnected();
            return _client.ExchangeCommand<T>(packet, this, tree_id);
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// The session flags.
        /// </summary>
        public Smb2SessionResponseFlags Flags { get; internal set; }
        #endregion

        #region Public Methods
        /// <summary>
        /// Connect to a SMB2 share.
        /// </summary>
        /// <param name="path">The share path to connect to. e.g. IPC$</param>
        /// <returns>The connected share.</returns>
        public Smb2Share ConnectShare(string path)
        {
            if (!path.StartsWith(@"\\"))
            {
                path = $@"\\{_client.Hostname}\{path.TrimStart('\\')}";
            }

            var response = ExchangeCommand<Smb2TreeConnectResponsePacket>(new Smb2TreeConnectRequestPacket(path));
            return response.Response.ToShare(this, path, response.Header.TreeId);
        }

        /// <summary>
        /// Connect to the IPC$ SMB2 share.
        /// </summary>
        /// <returns>The connected share.</returns>
        public Smb2Share ConnectIpcShare()
        {
            return ConnectShare("IPC$");
        }

        /// <summary>
        /// Logoff this session.
        /// </summary>
        public void Logoff()
        {
            if (_logoff)
                return;
            try
            {
                ExchangeCommand<Smb2IgnoredResponsePacket>(new Smb2LogoffRequestPackaget());
            }
            finally
            {
                _logoff = true;
            }
        }
        #endregion

        #region IDisposable Implementation
        void IDisposable.Dispose()
        {
            try
            {
                Logoff();
            }
            catch
            {
            }
        }
        #endregion
    }
}
