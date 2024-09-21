//  Copyright 2021 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Net.Tls;
using NtApiDotNet.Utilities.Text;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Schannel
{
    /// <summary>
    /// Authentication token for Schannel and CredSSP.
    /// </summary>
    /// <remarks>This is a simple parser for the TLS record format.</remarks>
    public class SchannelAuthenticationToken : AuthenticationToken
    {
        #region Public Properties
        /// <summary>
        /// List of TLS records.
        /// </summary>
        public IReadOnlyList<TlsRecord> Records { get; }
        #endregion

        #region Public Methods
        /// <summary>
        /// Format the authentication token.
        /// </summary>
        /// <returns>The token as a formatted string.</returns>
        public override string Format()
        {
            StringBuilder builder = new StringBuilder();
            int index = 0;
            foreach (var record in Records)
            {
                builder.AppendLine($"SChannel Record {index++}");
                builder.AppendLine($"Type   : {record.Type}");
                builder.AppendLine($"Version: {record.Version}");
                builder.AppendLine("Data    :");
                HexDumpBuilder hex_builder = new HexDumpBuilder(true, true, true, false, 0);
                hex_builder.Append(record.Data);
                hex_builder.Complete();
                builder.AppendLine(hex_builder.ToString());
            }
            return builder.ToString();
        }
        #endregion

        #region Constructors

        internal SchannelAuthenticationToken(byte[] data, List<TlsRecord> records) : base(data)
        {
            Records = records.AsReadOnly();
        }

        #endregion

        #region Internal Static Methods
        /// <summary>
        /// Try and parse data into an SChannel authentication token.
        /// </summary>
        /// <param name="data">The data to parse.</param>
        /// <param name="token">The SChannel authentication token.</param>
        /// <param name="client">True if this is a token from a client.</param>
        /// <param name="token_count">The token count number.</param>
        /// <returns>True if parsed successfully.</returns>
        internal static bool TryParse(byte[] data, int token_count, bool client, out SchannelAuthenticationToken token)
        {
            token = null;
            MemoryStream stm = new MemoryStream(data);
            BinaryReader reader = new BinaryReader(stm);
            List<TlsRecord> records = new List<TlsRecord>();
            while (stm.RemainingLength() > 0)
            {
                if (!TlsRecord.TryParse(reader, out TlsRecord record))
                {
                    return false;
                }
                records.Add(record);
            }
            token = new SchannelAuthenticationToken(data, records);
            return true;
        }
        #endregion
    }
}
