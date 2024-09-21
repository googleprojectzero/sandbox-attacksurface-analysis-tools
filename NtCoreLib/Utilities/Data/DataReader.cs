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
    internal sealed class DataReader : BinaryReader
    {
        public DataReader(byte[] data) : base(new MemoryStream(data))
        {
        }

        public DataReader(Stream input) : base(input)
        {
        }

        public DataReader(Stream input, Encoding encoding) : base(input, encoding)
        {
        }

        public DataReader(Stream input, Encoding encoding, bool leaveOpen) : base(input, encoding, leaveOpen)
        {
        }

        public T ReadInt32Enum<T>() where T : Enum
        {
            return (T)(object)ReadInt32();
        }

        public T ReadUInt32Enum<T>() where T : Enum
        {
            return (T)(object)ReadUInt32();
        }

        public byte[] ReadAllBytes(int length)
        {
            byte[] ret = ReadBytes(length);
            if (ret.Length != length)
            {
                throw new EndOfStreamException();
            }
            return ret;
        }

        public byte[] ReadAllBytes(long position, int length)
        {
            long curr_pos = Position;
            try
            {
                Position = position;
                return ReadAllBytes(length);
            }
            finally
            {
                Position = curr_pos;
            }
        }

        public Guid ReadGuid()
        {
            return new Guid(ReadAllBytes(16));
        }

        public long Seek(long offset, SeekOrigin loc)
        {
            return BaseStream.Seek(offset, loc);
        }

        public long Position
        {
            get => BaseStream.Position;
            set => BaseStream.Position = value;
        }

        public long Length => BaseStream.Length;

        public long RemainingLength => BaseStream.Length - BaseStream.Position;
    }
}
