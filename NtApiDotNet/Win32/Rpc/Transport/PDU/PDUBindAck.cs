//  Copyright 2020 Google Inc. All Rights Reserved.
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
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Rpc.Transport.PDU
{
    internal class PDUBindAck : PDUBase
    {
        public ushort MaxXmitFrag { get; }
        public ushort MaxRecvFrag { get; }
        public int AssocGroupId { get; }
        public string SecondaryAddress { get; }
        public List<ContextResult> ResultList { get; }

        public PDUBindAck(byte[] data, bool alter_context) 
            : base(alter_context ? PDUType.AlterContext : PDUType.Bind)
        {
            MemoryStream stm = new MemoryStream(data);
            BinaryReader reader = new BinaryReader(stm, Encoding.ASCII);
            MaxXmitFrag = reader.ReadUInt16();
            MaxRecvFrag = reader.ReadUInt16();
            AssocGroupId = reader.ReadInt32();
            int port_len = reader.ReadUInt16();
            SecondaryAddress = new string(reader.ReadChars(port_len)).TrimEnd('\0');
            long padding = stm.Position % 4;
            if (padding != 0)
            {
                stm.Position += (4 - padding);
            }
            ResultList = ContextResult.ReadList(reader);
        }
    }
}
