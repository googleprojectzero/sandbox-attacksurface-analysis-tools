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

namespace NtApiDotNet.Utilities.ASN1
{
    internal static class DERUtils
    {
        public static int ReadLength(this BinaryReader reader)
        {
            int length = reader.ReadByte();
            if ((length & 0x80) == 0)
                return length;

            int count = length & 0x7F;
            length = 0;
            for (int i = 0; i < count; ++i)
            {
                length <<= 8;
                length |= reader.ReadByte();
            }
            return length;
        }

        public static int ReadEncodedInt(this BinaryReader reader)
        {
            int value = 0;
            while (true)
            {
                byte next = reader.ReadByte();
                value <<= 7;
                value |= next & 0x7F;
                if ((next & 0x80) == 0)
                    break;
            }
            return value;
        }

        public static DERValue ReadValue(this BinaryReader reader, long offset)
        {
            DERValue ret = new DERValue();
            ret.Offset = offset + reader.BaseStream.Position;
            byte id = reader.ReadByte();
            ret.Type = (DERTagType)(id >> 6);
            ret.Constructed = (id & 0x20) != 0;
            ret.Tag = id & 0x1F;
            if (ret.Tag == 0x1F)
            {
                ret.Tag = reader.ReadEncodedInt();
            }
            // TODO: Handle indefinite length?
            int length = reader.ReadLength();
            ret.DataOffset = offset + reader.BaseStream.Position;
            ret.Data = reader.ReadBytes(length);
            if (ret.Data.Length != length)
                throw new EndOfStreamException();
            return ret;
        }

        public static long RemainingLength(this BinaryReader reader)
        {
            return reader.BaseStream.Length - reader.BaseStream.Position;
        }

        public static string ReadObjID(byte[] data)
        {
            List<int> values = new List<int>();
            BinaryReader reader = new BinaryReader(new MemoryStream(data));
            byte first = reader.ReadByte();
            values.Add(first / 40);
            values.Add(first % 40);
            while (reader.RemainingLength() > 0)
            {
                values.Add(reader.ReadEncodedInt());
            }
            return string.Join(".", values);
        }
    }
}
