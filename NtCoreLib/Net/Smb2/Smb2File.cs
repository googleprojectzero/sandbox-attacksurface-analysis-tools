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
using System.IO;

namespace NtApiDotNet.Net.Smb2
{
    /// <summary>
    /// Class to represent a connected SMB2 file.
    /// </summary>
    public sealed class Smb2File : IDisposable
    {
        #region Private Members
        private readonly Smb2Share _share;
        private readonly Smb2FileId _file_id;
        private bool _closed;

        private void CheckClosed()
        {
            if (_closed)
                throw new ObjectDisposedException(nameof(_file_id), "File object is closed.");
        }

        private byte[] QueryInformation(Smb2InfoType info_type, int output_buffer_length, int info_class = 0, 
            uint additional_information = 0, int flags = 0, byte[] input_buffer = null)
        {
            CheckClosed();
            output_buffer_length = Math.Min(output_buffer_length, _share.Client.MaxTransactionSize);
            return _share.ExchangeCommand<Smb2QueryInfoResponsePacket>(
                new Smb2QueryInfoRequestPacket(info_type, output_buffer_length, _file_id)
                {
                    FileInfoClass = info_class,
                    AdditionalInformation = additional_information,
                    Flags = flags,
                    InputBuffer = input_buffer
                }).Response.Data;
        }

        private void SetInformation(Smb2InfoType info_type, byte[] input_buffer, int info_class = 0,
            uint additional_information = 0)
        {
            CheckClosed();
            if (input_buffer is null)
            {
                throw new ArgumentNullException(nameof(input_buffer));
            }

            if (input_buffer.Length > _share.Client.MaxTransactionSize)
                throw new ArgumentOutOfRangeException("SET_INFO buffer is larger than maximum allowed size.");
            _share.ExchangeCommand<Smb2IgnoredResponsePacket>(
                new Smb2SetInfoRequestPacket(info_type, input_buffer, _file_id)
                {
                    FileInfoClass = info_class,
                    AdditionalInformation = additional_information
                });
        }
        #endregion

        #region Internal Members
        internal Smb2File(Smb2Share share, string name, Smb2CreateResponsePacket response)
        {
            _share = share;
            _file_id = response.FileId;
            Name = name;
            OplockLevel = response.OplockLevel;
            CreateAction = response.CreateAction;
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// The opened oplock level.
        /// </summary>
        public Smb2OplockLevel OplockLevel { get; }

        /// <summary>
        /// The creation action.
        /// </summary>
        public FileOpenResult CreateAction { get; }

        /// <summary>
        /// The name of the file.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// The full path to the file.
        /// </summary>
        public string FullPath => Path.Combine(_share.Path, Name);
        #endregion

        #region Public Methods
        /// <summary>
        /// Write to the file.
        /// </summary>
        /// <param name="data">The data to write.</param>
        /// <param name="offset">The offset to write to.</param>
        /// <returns>The number of bytes written.</returns>
        public int Write(byte[] data, long offset)
        {
            CheckClosed();
            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            int ofs = 0;
            while (ofs < data.Length)
            {
                int next_length = Math.Min(data.Length - ofs, _share.Client.MaxWriteSize);
                int length = _share.ExchangeCommand<Smb2WriteResponsePacket>(
                    new Smb2WriteRequestPacket(data, ofs, next_length, offset, _file_id)).Response.Count;
                if (length == 0)
                    break;
                ofs += length;
            }
            return ofs;
        }

        /// <summary>
        /// Read from the file.
        /// </summary>
        /// <param name="length">The number of bytes to read.</param>
        /// <param name="offset">The offset to write to.</param>
        /// <returns>The bytes read. Might be fewer bytes than requested.</returns>
        public byte[] Read(int length, long offset)
        {
            CheckClosed();

            length = Math.Min(length, _share.Client.MaxReadSize);
            return _share.ExchangeCommand<Smb2ReadResponsePacket>(
                new Smb2ReadRequestPacket(length, offset, _file_id)).Response.Data;
        }

        /// <summary>
        /// Method to query information for this file.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="output_buffer_length">The maximum output buffer size.</param>
        /// <returns>The queried data. Can be smaller than maximum.</returns>
        public byte[] QueryInformation(FileInformationClass info_class, int output_buffer_length)
        {
            return QueryInformation(Smb2InfoType.File, output_buffer_length, (int)info_class);
        }

        /// <summary>
        /// Method to set information for this file.
        /// </summary>
        /// <param name="info_class">The information class.</param>
        /// <param name="buffer">The buffer to set data from.</param>
        public void SetInformation(FileInformationClass info_class, byte[] buffer)
        {
            SetInformation(Smb2InfoType.File, buffer, (int)info_class);
        }

        /// <summary>
        /// Get the security descriptor specifying which parts to retrieve
        /// </summary>
        /// <param name="security_information">What parts of the security descriptor to retrieve</param>
        /// <returns>The security descriptor</returns>
        public SecurityDescriptor GetSecurityDescriptor(SecurityInformation security_information)
        {
            return SecurityDescriptor.Parse(QueryInformation(Smb2InfoType.Security, _share.Client.MaxTransactionSize, 
                additional_information: (uint)security_information), NtType.GetTypeByType<NtFile>(), true).Result;
        }

        /// <summary>
        /// Set the object's security descriptor
        /// </summary>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <param name="security_information">What parts of the security descriptor to set</param>
        public void SetSecurityDescriptor(SecurityDescriptor security_descriptor, SecurityInformation security_information)
        {
            SetInformation(Smb2InfoType.Security, security_descriptor.ToByteArray(), additional_information: (uint)security_information);
        }

        /// <summary>
        /// Close the SMB2 file.
        /// </summary>
        public void Close()
        {
            if (_closed)
                return;

            try
            {
                _share.ExchangeCommand<Smb2IgnoredResponsePacket>(new Smb2CloseRequestPacket(_file_id));
            }
            finally
            {
                _closed = true;
            }
        }
        #endregion

        #region IDisposable Implementation
        void IDisposable.Dispose()
        {
            Close();
        }
        #endregion
    }
}
