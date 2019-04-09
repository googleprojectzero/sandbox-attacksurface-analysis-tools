//  Copyright 2019 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Utilities.Text;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NtApiDotNet.Ndr
{
#pragma warning disable 1591
    /// <summary>
    /// A buffer to unmarshal NDR data from.
    /// </summary>
    /// <remarks>This class is primarily for internal use only.</remarks>
    public class NdrUnmarshalBuffer : IDisposable
    {
        private readonly MemoryStream _stm;
        private readonly BinaryReader _reader;
        private readonly DisposableList<NtObject> _handles;
        private readonly List<Action> _deferred_reads;

        private static int CaclulateAlignment(int offset, int alignment)
        {
            int result = alignment - (offset % alignment);
            if (result < alignment)
            {
                return result;
            }
            return 0;
        }

        public void Align(int alignment)
        {
            _stm.Position += CaclulateAlignment((int)_stm.Position, alignment);
        }

        public NdrUnmarshalBuffer(byte[] buffer, IEnumerable<NtObject> handles)
        {
            _stm = new MemoryStream(buffer);
            _reader = new BinaryReader(_stm, Encoding.Unicode);
            _handles = new DisposableList<NtObject>(handles);
            _deferred_reads = new List<Action>();
        }

        public NdrUnmarshalBuffer(byte[] buffer) 
            : this(null, new NtObject[0])
        {
        }

        public byte ReadByte()
        {
            return _reader.ReadByte();
        }

        public byte[] ReadBytes(int count)
        {
            byte[] ret = _reader.ReadBytes(count);
            if (ret.Length < count)
            {
                throw new EndOfStreamException();
            }
            return ret;
        }

        public char[] ReadChars(int count)
        {
            char[] chars = _reader.ReadChars(count);
            if (chars.Length < count)
            {
                throw new EndOfStreamException();
            }
            return chars;
        }

        public sbyte ReadSByte()
        {
            return _reader.ReadSByte();
        }

        public short ReadInt16()
        {
            Align(2);
            return _reader.ReadInt16();
        }

        public ushort ReadUInt16()
        {
            Align(2);
            return _reader.ReadUInt16();
        }

        public int ReadInt32()
        {
            Align(4);
            return _reader.ReadInt32();
        }

        public uint ReadUInt32()
        {
            Align(4);
            return _reader.ReadUInt32();
        }

        public long ReadInt64()
        {
            Align(8);
            return _reader.ReadInt64();
        }

        public ulong ReadUInt64()
        {
            Align(8);
            return _reader.ReadUInt64();
        }

        public float ReadFloat()
        {
            Align(4);
            return _reader.ReadSingle();
        }

        public NdrInt3264 ReadInt3264()
        {
            return new NdrInt3264(ReadInt32());
        }

        public NdrUInt3264 ReadUInt3264()
        {
            return new NdrUInt3264(ReadUInt32());
        }

        public double ReadDouble()
        {
            Align(8);
            return _reader.ReadDouble();
        }

        public int ReadReferent()
        {
            // Might need to actually handle referents, guess we'll see.
            return ReadInt32();
        }

        public string ReadFixedString(int count)
        {
            return new string(ReadChars(count));
        }

        public string ReadAnsiConformantString()
        {
            int max_count = ReadInt32();
            int offset = ReadInt32();
            int actual_count = ReadInt32();

            return BinaryEncoding.Instance.GetString(_reader.ReadBytes(actual_count)).TrimEnd('\0');
        }

        public string ReadConformantString()
        {
            int max_count = ReadInt32();
            int offset = ReadInt32();
            int actual_count = ReadInt32();

            return new string(_reader.ReadChars(actual_count)).TrimEnd('\0');
        }

        public T ReadUniquePointer<T>(Func<T> read_func) where T : class
        {
            int referent = ReadInt32();
            if (referent == 0)
            {
                return null;
            }
            return read_func();
        }

        public Guid ReadGuid()
        {
            Align(4);
            return new Guid(ReadBytes(16));
        }

        public T ReadStruct<T>() where T : INdrStructure, new()
        {
            T ret = new T();
            ret.Unmarshal(this);
            return ret;
        }

        public T ReadSystemHandle<T>() where T : NtObject
        {
            int index = ReadInt32();
            if (!NtObjectUtils.IsWindows81OrLess)
            {
                // Unsure what this is on Windows 10. This isn't used on Windows 8.X.
                ReadInt32();
            }

            return (T)_handles[index - 1].DuplicateObject();
        }

        public NdrContextHandle ReadContextHandle()
        {
            int attributes = ReadInt32();
            Guid uuid = ReadGuid();
            return new NdrContextHandle(attributes, uuid);
        }

        public T ReadPointer<T>(Func<T> unmarshal_func) where T : class
        {
            int referent = ReadReferent();
            if (referent == 0)
            {
                return null;
            }
            return unmarshal_func();
        }

        public T ReadPointer<T, U>(Func<U, T> unmarshal_func, U arg) where T : class
        {
            return ReadPointer(() => unmarshal_func(arg));
        }

        public T ReadPointer<T, U, V>(Func<U, V, T> unmarshal_func, U arg, V arg2) where T : class
        {
            return ReadPointer(() => unmarshal_func(arg, arg2));
        }

        public NdrEmbeddedPointer<T> ReadEmbeddedPointer<T>(Func<T> unmarshal_func)
        {
            int referent = ReadReferent();
            if (referent == 0)
            {
                return null;
            }

            // Really should have referents, but I'm not convinced the MSRPC NDR engine uses them.
            // Perhaps introduce a lazy method to bind it after the fact.
            var deferred_reader = NdrEmbeddedPointer<T>.CreateDeferredReader(unmarshal_func);
            _deferred_reads.Add(deferred_reader.Item2);
            return deferred_reader.Item1;
        }

        public NdrEmbeddedPointer<T> ReadEmbeddedPointer<T, U>(Func<U, T> unmarshal_func, U arg)
        {
            return ReadEmbeddedPointer(() => unmarshal_func(arg));
        }

        public NdrEmbeddedPointer<T> ReadEmbeddedPointer<T, U, V>(Func<U, V, T> unmarshal_func, U arg, V arg2)
        {
            return ReadEmbeddedPointer(() => unmarshal_func(arg, arg2));
        }

        public NdrEmbeddedPointer<T> ReadEmbeddedStructPointer<T>() where T : INdrStructure, new()
        {
            return ReadEmbeddedPointer(() => ReadStruct<T>());
        }

        public T[] ReadVaryingBogusArrayStruct<T>() where T : INdrStructure, new()
        {
            return ReadVaryingBogusArray(() => ReadStruct<T>());
        }

        public T[] ReadVaryingBogusArray<T>(Func<T> reader)
        {
            // We don't really care about conformance or variance as we're not going to
            // validate anything.
            int offset = ReadInt32();
            int actual_count = ReadInt32();
            T[] ret = new T[actual_count];
            for (int i = 0; i < actual_count; ++i)
            {
                ret[i] = reader();
            }
            return ret;
        }

        public NdrUnsupported ReadUnsupported(string name)
        {
            throw new NotImplementedException($"Reading type {name} is unsupported");
        }

        public void PopuluateDeferredPointers()
        {
            foreach (var a in _deferred_reads)
            {
                a();
            }
            _deferred_reads.Clear();
        }

        public virtual void Dispose()
        {
            _handles.Dispose();
        }
    }
#pragma warning restore 1591
}
