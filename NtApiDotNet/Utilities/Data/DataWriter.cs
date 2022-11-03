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

using System;
using System.IO;
using System.Text;

namespace NtApiDotNet.Utilities.Data
{
    internal sealed class DataWriter : BinaryWriter
    {
        public DataWriter() : base(new MemoryStream())
        {
        }

        public DataWriter(Stream output) : base(output)
        {
        }

        public DataWriter(Stream output, Encoding encoding) : base(output, encoding)
        {
        }

        public DataWriter(Stream output, Encoding encoding, bool leaveOpen) : base(output, encoding, leaveOpen)
        {
        }

        public void WriteGuid(Guid guid)
        {
            Write(guid.ToByteArray());
        }

        public void WriteInt32Enum(Enum value)
        {
            Write((int)(object)value);
        }

        public void WriteUInt32Enum(Enum value)
        {
            Write((uint)(object)value);
        }

        public void WriteByte(int value)
        {
            Write((byte)value);
        }

        public byte[] ToArray()
        {
            if (BaseStream is MemoryStream stm)
            {
                return stm.ToArray();
            }
            throw new InvalidOperationException("Base stream is not a MemoryStream.");
        }
    }
}
