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

using System.IO;

namespace NtApiDotNet.Win32.Rpc.Transport.PDU
{
    internal class PDUFault : PDUBase
    {
        public int AllocHint { get; }
        public ushort ContextId { get; }
        public byte CancelCount { get; }
        public int Status { get; }
        public byte[] ExtendedErrorData { get; }

        public PDUFault(byte[] data) : base(PDUType.Fault)
        {
            MemoryStream stm = new MemoryStream(data);
            BinaryReader reader = new BinaryReader(stm);
            AllocHint = reader.ReadInt32();
            ContextId = reader.ReadUInt16();
            CancelCount = reader.ReadByte();
            bool extended_error_present = reader.ReadByte() != 0;
            Status = reader.ReadInt32();
            reader.ReadInt32(); // Reserved.
            if (extended_error_present)
            {
                try
                {
                    ExtendedErrorData = reader.ReadBytes(AllocHint - 0x20);
                }
                catch (EndOfStreamException)
                {
                }
            }
        }
    }
}
