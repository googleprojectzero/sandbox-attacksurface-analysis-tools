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

using NtApiDotNet.Utilities.Data;
using System;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.NegoEx
{
    /// <summary>
    /// Base class for a NEGOEX message.
    /// </summary>
    public abstract class NegoExMessage
    {
        private readonly NegoExMessageHeader _header;

        private protected static string FormatAuthScheme(Guid guid)
        {
            string name = NegoExAuthSchemes.GetName(guid);
            if (name.Length > 0)
                return $"{guid} ({name})";
            return guid.ToString();
        }

        internal static byte[] ReadByteVector(DataReader reader, byte[] data)
        {
            int byte_ofs = reader.ReadInt32();
            int byte_len = reader.ReadInt32();

            byte[] ret = new byte[byte_len];
            Buffer.BlockCopy(data, byte_ofs, ret, 0, byte_len);
            return ret;
        }

        /// <summary>
        /// The type of NEGOEX message.
        /// </summary>
        public NegoExMessageType Type => _header.MessageType;

        /// <summary>
        /// The message sequence number.
        /// </summary>
        public uint SequenceNum => _header.SequenceNum;

        /// <summary>
        /// The conversation ID.
        /// </summary>
        public Guid ConversationId => _header.ConversationId;

        private protected NegoExMessage(NegoExMessageHeader header)
        {
            _header = header;
        }

        private protected abstract void InnerFormat(StringBuilder builder);

        internal void Format(StringBuilder builder)
        {
            builder.AppendLine($"<NEGOEX {Type} Message>");
            InnerFormat(builder);
            builder.AppendLine($"</NEGOEX {Type} Message>");
        }
    }
}
