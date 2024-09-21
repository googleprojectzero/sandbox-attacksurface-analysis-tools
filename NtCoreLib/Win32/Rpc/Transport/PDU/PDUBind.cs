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

using System.Collections.Generic;
using System.IO;

namespace NtCoreLib.Win32.Rpc.Transport.PDU;

internal class PDUBind : PDUBase
{
    public PDUBind(ushort max_xmit_frag, ushort max_recv_frag, int assoc_group_id, bool alter_context) 
        : base(alter_context ? PDUType.AlterContext : PDUType.Bind)
    {
        _max_xmit_frag = max_xmit_frag;
        _max_recv_frag = max_recv_frag;
        _assoc_group_id = assoc_group_id;
        Elements = new List<ContextElement>();
    }

    private readonly ushort _max_xmit_frag;
    private readonly ushort _max_recv_frag;
    private readonly int _assoc_group_id;

    public List<ContextElement> Elements { get; }

    public override byte[] ToArray()
    {
        MemoryStream stm = new();
        BinaryWriter writer = new(stm);
        writer.Write(_max_xmit_frag);
        writer.Write(_max_recv_frag);
        writer.Write(_assoc_group_id);
        ContextElement.WriteList(writer, Elements);
        return stm.ToArray();
    }
}
