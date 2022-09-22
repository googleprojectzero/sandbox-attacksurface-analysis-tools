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
using NtApiDotNet.Win32.Security.Authentication;
using System;
using System.IO;

namespace NtApiDotNet.Net.Smb
{
    /// <summary>
    /// Class to represent a single named pipe connection to an SMB server.
    /// </summary>
    public sealed class Smb2NamedPipeFile : IDisposable
    {
        #region Private Members
        private Smb2Client _client;
        private Smb2Session _session;
        private Smb2Share _share;
        private Smb2File _file;
        private Lazy<FilePipeInformation> _pipe_information;

        private Smb2NamedPipeFile()
        {
            _pipe_information = new Lazy<FilePipeInformation>(GetPipeInformation);
        }

        private FilePipeInformation GetPipeInformation()
        {
            MemoryStream stm = new MemoryStream(_file.QueryInformation(FileInformationClass.FilePipeInformation, 8));
            BinaryReader reader = new BinaryReader(stm);

            return new FilePipeInformation
            {
                ReadMode = (NamedPipeReadMode)reader.ReadInt32(),
                CompletionMode = (NamedPipeCompletionMode)reader.ReadInt32()
            };
        }

        private void SetPipeInformation(NamedPipeReadMode read_mode, NamedPipeCompletionMode completion_mode)
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            writer.Write((int)read_mode);
            writer.Write((int)completion_mode);
            _file.SetInformation(FileInformationClass.FilePipeInformation, stm.ToArray());
            _pipe_information = new Lazy<FilePipeInformation>(GetPipeInformation);
        }
        #endregion

        /// <summary>
        /// The name of the file.
        /// </summary>
        public string Name => _file.Name;

        /// <summary>
        /// The full path to the file.
        /// </summary>
        public string FullPath => _file.FullPath;

        /// <summary>
        /// Write to the file.
        /// </summary>
        /// <param name="data">The data to write.</param>
        /// <returns>The number of bytes written.</returns>
        public int Write(byte[] data) => _file.Write(data, 0);

        /// <summary>
        /// Read from the file.
        /// </summary>
        /// <param name="length">The number of bytes to read.</param>
        /// <returns>The bytes read. Might be fewer bytes than requested.</returns>
        public byte[] Read(int length) => _file.Read(length, 0);

        /// <summary>
        /// Open a named pipe on a SMB2 server.
        /// </summary>
        /// <param name="hostname">The hostname of the SMB2 server.</param>
        /// <param name="name">The name of the pipe to open.</param>
        /// <param name="desired_access">The desired access for the open.</param>
        /// <param name="credentials">Credentials for the open.</param>
        /// <param name="impersonation_level">Specify impersonation level for named pipe.</param>
        /// <returns>The opened named pipe file.</returns>
        public static Smb2NamedPipeFile Open(string hostname, string name, 
            FileAccessRights desired_access = FileAccessRights.MaximumAllowed, 
            UserCredentials credentials = null, 
            SecurityImpersonationLevel impersonation_level = SecurityImpersonationLevel.Impersonation)
        {
            if (string.IsNullOrWhiteSpace(hostname))
            {
                throw new ArgumentException($"'{nameof(hostname)}' cannot be null or whitespace.", nameof(hostname));
            }

            if (name is null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            Smb2NamedPipeFile ret = new Smb2NamedPipeFile();
            try
            {
                ret._client = new Smb2Client(hostname);
                ret._session = ret._client.CreateSession(credentials);
                ret._share = ret._session.ConnectIpcShare();
                ret._file = ret._share.Open(name, desired_access, impersonation_level: impersonation_level);
                return ret;
            }
            catch
            {
                ret.Close();
                throw;
            }
        }

        /// <summary>
        /// Pipe completion mode.
        /// </summary>
        public NamedPipeCompletionMode CompletionMode
        {
            get => _pipe_information.Value.CompletionMode;
            set => SetPipeInformation(ReadMode, value);
        }

        /// <summary>
        /// Pipe read mode.
        /// </summary>
        public NamedPipeReadMode ReadMode
        {
            get => _pipe_information.Value.ReadMode;
            set => SetPipeInformation(value, CompletionMode);
        }

        /// <summary>
        /// Close the named pipe;
        /// </summary>
        public void Close()
        {
            _file?.Close();
            _file = null;
            _share?.Disconnect();
            _share = null;
            _session?.Logoff();
            _session = null;
            _client.Close();
            _client = null;
        }

        void IDisposable.Dispose()
        {
            try
            {
                Close();
            }
            catch
            {
            }
        }
    }
}
