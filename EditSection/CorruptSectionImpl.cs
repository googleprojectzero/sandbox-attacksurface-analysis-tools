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

namespace EditSection;

enum CorruptSectionOperation
{
    Overwrite,
    And,
    Or,
    Xor
}

abstract class CorruptSectionBase : ICorruptSection
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

    internal static void ApplyOperationToArray(byte[] array, Func<byte> generator, CorruptSectionOperation op)
    {
        for (int i = 0; i < array.Length; ++i)
        {
            array[i] = ApplyOperationToByte(array[i], generator(), op);
        }
    }

    private readonly CorruptSectionOperation _op;
    private const int CHUNK_LENGTH = 64 * 1024;

    protected CorruptSectionBase(CorruptSectionOperation op)
    {
        _op = op;
    }

    protected abstract Func<byte> GetGenerator();

    public void Corrupt(NativeMappedFileByteProvider prov, long start, long end)
    {
        try
        {
            prov.DisableByteWritten(true);
            long total_length = end - start;
            long chunks = total_length / CHUNK_LENGTH;
            long remaining = total_length % CHUNK_LENGTH;
            var generator = GetGenerator();
            byte[] temp_chunk = new byte[CHUNK_LENGTH];

            for (long chunk = 0; chunk < chunks; ++chunk)
            {
                long ofs = start + (chunk * CHUNK_LENGTH);
                // No point reading chunk if we're just going to overwrite it.
                byte[] data = _op == CorruptSectionOperation.Overwrite ? temp_chunk : prov.ReadBytes(ofs, CHUNK_LENGTH);
                ApplyOperationToArray(data, generator, _op);
                prov.WriteBytes(ofs, data);
            }

            if (remaining > 0)
            {
                long ofs = start + (chunks * CHUNK_LENGTH);
                byte[] data = _op == CorruptSectionOperation.Overwrite ? temp_chunk : prov.ReadBytes(ofs, (int)remaining);
                ApplyOperationToArray(data, generator, _op);
                prov.WriteBytes(ofs, data);
            }
        }
        finally
        {
            prov.DisableByteWritten(false);
        }
    }
}

class CorruptSectionFixedValue : CorruptSectionBase
{
    private readonly byte[] _data;
    public CorruptSectionFixedValue(byte[] data, CorruptSectionOperation op) : base(op)
    {
        if (data.Length < 1)
        {
            throw new ArgumentException("Data array must contain at least one byte");
        }

        _data = (byte[])data.Clone();
    }

    protected override Func<byte> GetGenerator()
    {
        int data_pos = 0;
        return () =>
        {
            byte ret = _data[data_pos++];
            data_pos %= _data.Length;
            return ret;
        };
    }
}

class CorruptSectionRandomValue : CorruptSectionBase
{
    private readonly Random _rand;
    private readonly int _low_byte;
    private readonly int _high_byte;
    
    public CorruptSectionRandomValue(byte low_byte, byte high_byte, CorruptSectionOperation op) : base(op)
    {
        _rand = new Random();
        _low_byte = low_byte;
        _high_byte = high_byte + 1;
    }

    protected override Func<byte> GetGenerator()
    {
        return () => (byte)_rand.Next(_low_byte, _high_byte);
    }
}
