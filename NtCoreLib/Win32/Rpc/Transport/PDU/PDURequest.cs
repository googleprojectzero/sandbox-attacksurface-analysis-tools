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

namespace NtCoreLib.Win32.Rpc.Transport.PDU;

internal class PDURequest
{
    public int AllocHint { get; set; }
    public ushort ContextId { get; set; }
    public short OpNum { get; set; }
    public Guid ObjectUUID { get; set; }
    public bool HasObjectUUID => ObjectUUID != Guid.Empty;
    public int HeaderLength => PDUHeader.PDU_HEADER_SIZE + 8 + (ObjectUUID != Guid.Empty ? 16 : 0);

    public byte[] ToArray(PDUHeader header, int stub_length, int auth_length)
    {
        MemoryStream stm = new();
        BinaryWriter writer = new(stm);
        header.AuthLength = checked((ushort)auth_length);
        header.FragmentLength = checked((ushort)(HeaderLength + stub_length + auth_length));
        header.Flags |= HasObjectUUID ? PDUFlags.ObjectUuid : 0;
        header.Write(writer);
        writer.Write(AllocHint);
        writer.Write(ContextId);
        writer.Write(OpNum);
        if (HasObjectUUID)
        {
            writer.Write(ObjectUUID.ToByteArray());
        }
        return stm.ToArray();
    }

    public static List<byte[]> DoFragment(byte[] stub_data, int max_frag_length)
    {
        List<byte[]> fragments = new();
        int remaining_length = stub_data.Length;
        int curr_offset = 0;
        do
        {
            int data_length = Math.Min(max_frag_length, remaining_length);
            MemoryStream stm = new();
            BinaryWriter writer = new(stm);
            writer.Write(stub_data, curr_offset, data_length);
            curr_offset += data_length;
            remaining_length -= data_length;
            fragments.Add(stm.ToArray());
        }
        while (remaining_length > 0);
        return fragments;
    }
}
