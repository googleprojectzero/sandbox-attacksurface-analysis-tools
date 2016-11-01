//  Copyright 2015 Google Inc. All Rights Reserved.
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

namespace EditSection
{
    enum CorruptSectionOperation
    {
        Overwrite,
        And,
        Or,
        Xor
    }

    class CorruptSectionFixedValue : ICorruptSection
    {
        internal static byte ApplyOperationToByte(byte left, byte right, CorruptSectionOperation op)
        {
            switch (op)
            {
                case CorruptSectionOperation.Xor:
                    return (byte)(left ^ right);                    
                case CorruptSectionOperation.And:
                    return (byte)(left & right);                    
                case CorruptSectionOperation.Or:
                    return (byte)(left | right);                    
                default:
                    return right;                    
            }
        }

        byte[] _data;
        CorruptSectionOperation _op;

        public CorruptSectionFixedValue(byte[] data, CorruptSectionOperation op)
        {
            _data = (byte[])data.Clone();
            _op = op;
        }

        public void Corrupt(Be.Windows.Forms.IByteProvider prov, long start, long end)
        {
            if (_data.Length > 0)
            {
                int data_pos = 0;
                for (long i = start; i < end; ++i)
                {
                    prov.WriteByte(i, ApplyOperationToByte(prov.ReadByte(i), _data[data_pos], _op));
                    data_pos = (data_pos + 1) % _data.Length;
                }
            }
        }
    }

    class CorruptSectionRandomValue : ICorruptSection
    {
        Random _rand;
        int _low_byte;
        int _high_byte;
        CorruptSectionOperation _op;

        public CorruptSectionRandomValue(byte low_byte, byte high_byte, CorruptSectionOperation op)
        {
            _rand = new Random();
            _low_byte = low_byte;
            _high_byte = high_byte + 1;
            _op = op;
        }

        public void Corrupt(Be.Windows.Forms.IByteProvider prov, long start, long end)
        {
            for (long i = start; i < end; ++i)
            {
                prov.WriteByte(i, CorruptSectionFixedValue.ApplyOperationToByte(prov.ReadByte(i), 
                    (byte)_rand.Next(_low_byte, _high_byte), _op));                
            }     
        }
    }
}
