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

namespace NtApiDotNet.Net.Smb
{
    /// <summary>
    /// Class to represent a connected SMB2 file.
    /// </summary>
    public sealed class Smb2File : IDisposable
    {
        private readonly Smb2Share _share;
        private readonly Guid _file_id;
        private bool _closed;

        private void CheckClosed()
        {
            if (_closed)
                throw new ObjectDisposedException(nameof(_file_id), "File object is closed.");
        }

        internal Smb2File(Smb2Share share, string name, Smb2CreateResponsePacket response)
        {
            _share = share;
            _file_id = response.FileId;
            Name = name;
            OplockLevel = response.OplockLevel;
            CreateAction = response.CreateAction;
        }

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

        void IDisposable.Dispose()
        {
            Close();
        }
    }
}
