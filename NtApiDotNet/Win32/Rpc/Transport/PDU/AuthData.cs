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

using System.IO;

namespace NtApiDotNet.Win32.Rpc.Transport.PDU
{
    internal struct AuthData
    {
        public const int PDU_AUTH_DATA_HEADER_SIZE = 8;

        public RpcAuthenticationType Type;
        public RpcAuthenticationLevel Level;
        public int Padding;
        public int ContextId;
        public byte[] Data;

        public AuthData(RpcAuthenticationType type, RpcAuthenticationLevel level, int padding, int context_id, byte[] data)
        {
            Type = type;
            Level = level;
            Padding = padding;
            ContextId = context_id;
            Data = data;
        }

        public static byte[] ToArray(RpcTransportSecurity transport_security, int auth_padding_length, int context_id, byte[] security_data)
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            AuthData data = new AuthData(transport_security.AuthenticationType, transport_security.AuthenticationLevel,
                auth_padding_length, context_id, security_data);
            data.Write(writer, auth_padding_length);
            return stm.ToArray();
        }

        public static AuthData Read(BinaryReader reader, int auth_length)
        {
            RpcAuthenticationType type = (RpcAuthenticationType)reader.ReadByte();
            RpcAuthenticationLevel level = (RpcAuthenticationLevel)reader.ReadByte();
            int padding = reader.ReadByte();
            reader.ReadByte(); // Reserved;
            int context_id = reader.ReadInt32();
            return new AuthData(type, level, padding, context_id, reader.ReadAllBytes(auth_length));
        }

        public void Write(BinaryWriter writer, int padding)
        {
            writer.Write((byte)Type);
            writer.Write((byte)Level);
            writer.Write((byte)padding);
            writer.Write((byte)0); // Reserved.
            writer.Write(ContextId);
            writer.Write(Data);
        }
    }
}
