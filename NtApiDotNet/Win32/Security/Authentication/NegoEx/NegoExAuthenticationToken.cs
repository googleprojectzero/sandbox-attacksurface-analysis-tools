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
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.NegoEx
{
    /// <summary>
    /// Class for a NEGOEX authentication token.
    /// </summary>
    /// <remarks>Based on the MS-NEGOEX specification.</remarks>
    public sealed class NegoExAuthenticationToken : AuthenticationToken
    {
        /// <summary>
        /// The list of messages in this token. Can be one or more.
        /// </summary>
        public IReadOnlyList<NegoExMessage> Messages { get; }

        internal NegoExAuthenticationToken(List<NegoExMessage> messages, byte[] data) : base(data)
        {
            Messages = messages.AsReadOnly();
        }

        /// <summary>
        /// Format the authentication token.
        /// </summary>
        /// <returns>The token as a formatted string.</returns>
        public override string Format()
        {
            StringBuilder builder = new StringBuilder();
            foreach (var msg in Messages)
            {
                msg.Format(builder);
            }
            return builder.ToString();
        }

        /// <summary>
        /// Parse a NEGOEX token from a byte array.
        /// </summary>
        /// <param name="data">The byte array to parse.</param>
        /// <returns>The authentication token.</returns>
        public static NegoExAuthenticationToken Parse(byte[] data)
        {
            if (!TryParse(data, 0, false, out NegoExAuthenticationToken token))
                throw new InvalidDataException("Invalid NEGOEX token.");
            return token;
        }

        private static NegoExMessage ReadMessage(NegoExMessageHeader header, byte[] data)
        {
            switch (header.MessageType)
            {
                case NegoExMessageType.InitiatorNego:
                case NegoExMessageType.AcceptorNego:
                    return NegoExMessageNego.Parse(header, data);
                case NegoExMessageType.InitiatorMetaData:
                case NegoExMessageType.AcceptorMetaData:
                case NegoExMessageType.ApRequest:
                case NegoExMessageType.Challenge:
                    return NegoExMessageExchange.Parse(header, data);
                case NegoExMessageType.Verify:
                    return NegoExMessageVerify.Parse(header, data);
                case NegoExMessageType.Alert:
                    return NegoExMessageAlert.Parse(header, data);
                default:
                    throw new EndOfStreamException("Unknown message type.");
            }
        }

        internal static bool TryParse(byte[] data, int token_count, bool client, out NegoExAuthenticationToken token)
        {
            token = null;
            if (data.Length < NegoExMessageHeader.HEADER_SIZE)
                return false;
            try
            {
                DataReader reader = new DataReader(data);
                List<NegoExMessage> messages = new List<NegoExMessage>();
                while (reader.RemainingLength > 0)
                {
                    long current_pos = reader.Position;
                    if (!NegoExMessageHeader.TryParse(reader, out NegoExMessageHeader header))
                    {
                        return false;
                    }
                    reader.Position = current_pos;
                    byte[] message_data = reader.ReadAllBytes(header.cbMessageLength);

                    messages.Add(ReadMessage(header, message_data));
                }
                token = new NegoExAuthenticationToken(messages, data);
            }
            catch (EndOfStreamException)
            {
                return false;
            }
            return true;
        }
    }
}
