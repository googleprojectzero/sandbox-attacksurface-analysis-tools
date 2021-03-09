﻿//  Copyright 2021 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet.Net.Tls
{
    /// <summary>
    /// A class to represent a TLS record.
    /// </summary>
    public sealed class TlsRecord
    {
        #region Public Properties
        /// <summary>
        /// TLS record type.
        /// </summary>
        public TlsRecordType Type { get; }

        /// <summary>
        /// Version of protocol.
        /// </summary>
        public Version Version { get; }

        /// <summary>
        /// The record data.
        /// </summary>
        public byte[] Data { get; }
        #endregion

        #region Constructors

        internal TlsRecord(byte[] data, TlsRecordType record_type,
            int major_version, int minor_version, byte[] record_data)
        {
            Type = record_type;
            Version = new Version(major_version, minor_version);
            Data = record_data;
        }

        #endregion

        #region Static Methods
        /// <summary>
        /// Parse a TLS record from a binary reader.
        /// </summary>
        /// <param name="reader">The reader to read from.</param>
        /// <returns></returns>
        public TlsRecord Parse(BinaryReader reader)
        {
            if (!TryParse(reader, out TlsRecord record))
            {
                throw new ArgumentException("Invalid TLS record.");
            }
            return record;
        }
        #endregion

        #region Internal Members
        internal static bool TryParse(BinaryReader reader, out TlsRecord record)
        {
            record = null;
            try
            {
                TlsRecordType type = (TlsRecordType)reader.ReadByte();
                int major_version = reader.ReadByte();
                int minor_version = reader.ReadByte();
                int length = reader.ReadByte() << 8 | reader.ReadByte();
                byte[] data = reader.ReadAllBytes(length);
                record = new TlsRecord(data, type, major_version, minor_version, data);
                return true;
            }
            catch (EndOfStreamException)
            {
                return false;
            }
        }
        #endregion
    }
}
