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

using System.IO;

namespace NtApiDotNet.Utilities.ASN1
{
    internal class DERParserStream
    {
        private readonly MemoryStream _stm;
        private readonly BinaryReader _reader;
        private readonly long _offset;

        public DERParserStream(byte[] data, int index, int count, long offset)
        {
            _stm = new MemoryStream(data, index, count);
            _reader = new BinaryReader(_stm);
            _offset = offset;
        }

        public DERValue ReadValue()
        {
            DERValue ret = new DERValue();
            ret.Offset = _offset + _stm.Position;
            byte id = _reader.ReadByte();
            ret.Type = (DERTagType)(id >> 6);
            ret.Constructed = (id & 0x20) != 0;
            ret.Tag = id & 0x1F;
            if (ret.Tag == 0x1F)
            {
                ret.Tag = _reader.ReadEncodedInt();
            }
            // TODO: Handle indefinite length?
            int length = _reader.ReadLength();
            ret.DataOffset = _offset + _stm.Position;
            ret.Data = _reader.ReadAllBytes(length);
            return ret;
        }

        public bool Done => _stm.Position >= _stm.Length;
    }
}
