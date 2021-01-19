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

namespace NtApiDotNet.Win32.Rpc.Transport.PDU
{
    internal class PDURequest : PDUBase
    {
        public PDURequest() : base(PDUType.Request)
        {
        }

        public int AllocHint { get; set; }
        public ushort ContextId { get; set; }
        public short OpNum { get; set; }
        public Guid ObjectUUID { get; set; }
        public byte[] StubData { get; set; }
        public bool HasObjectUUID => ObjectUUID != Guid.Empty;

        public List<byte[]> DoFragment(int max_frag_length)
        {
            int header_length = 8 + (ObjectUUID != Guid.Empty ? 16 : 0);
            List<byte[]> fragments = new List<byte[]>();
            int remaining_length = StubData.Length;
            int curr_offset = 0;
            do
            {
                int data_length = Math.Min(max_frag_length - header_length, remaining_length);
                MemoryStream stm = new MemoryStream();
                BinaryWriter writer = new BinaryWriter(stm);
                writer.Write(AllocHint);
                writer.Write(ContextId);
                writer.Write(OpNum);
                if (ObjectUUID != Guid.Empty)
                {
                    writer.Write(ObjectUUID.ToByteArray());
                }
                writer.Write(StubData, curr_offset, data_length);
                curr_offset += data_length;
                remaining_length -= data_length;
                fragments.Add(stm.ToArray());
            }
            while (remaining_length > 0);
            return fragments;
        }
    }
}
