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

namespace NtApiDotNet.Ndr.Marshal
{
#pragma warning disable 1591
    /// <summary>
    /// A buffer to unmarshal NDR data from.
    /// </summary>
    /// <remarks>This class is primarily for internal use only.</remarks>
    public class NdrUnmarshalBuffer : IDisposable
    {
        #region Private Members

        private readonly MemoryStream _stm;
        private readonly BinaryReader _reader;
        private readonly DisposableList<NtObject> _handles;
        private readonly List<Action> _deferred_reads;

        private string[] ReadStringArray(int[] refs, Func<string> reader)
        {
            string[] ret = new string[refs.Length];
            for (int i = 0; i < refs.Length; ++i)
            {
                if (refs[i] == 0)
                {
                    ret[i] = string.Empty;
                }
                ret[i] = reader();
            }
            return ret;
        }

        private void CheckDataRepresentation(NdrDataRepresentation data_represenation)
        {
            if (data_represenation.IntegerRepresentation != NdrIntegerRepresentation.LittleEndian ||
                data_represenation.FloatingPointRepresentation != NdrFloatingPointRepresentation.IEEE ||
                data_represenation.CharacterRepresentation != NdrCharacterRepresentation.ASCII)
            {
                throw new ArgumentException("Unsupported NDR data representation");
            }
        }

        #endregion

        #region Constructors
        public NdrUnmarshalBuffer(byte[] buffer, IEnumerable<NtObject> handles, NdrDataRepresentation data_represenation)
        {
            _stm = new MemoryStream(buffer);
            _reader = new BinaryReader(_stm, Encoding.Unicode);
            _handles = new DisposableList<NtObject>(handles);
            _deferred_reads = new List<Action>();
            CheckDataRepresentation(data_represenation);
        }
        public NdrUnmarshalBuffer(byte[] buffer, IEnumerable<NtObject> handles) 
            : this(buffer, handles, new NdrDataRepresentation())
        {
        }

        public NdrUnmarshalBuffer(byte[] buffer)
            : this(buffer, new NtObject[0])
        {
        }
        #endregion

        #region Misc Methods

        public void Align(int alignment)
        {
            _stm.Position += NdrNativeUtils.CalculateAlignment((int)_stm.Position, alignment);
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

        public NdrUnsupported ReadUnsupported(string name)
        {
            throw new NotImplementedException($"Reading type {name} is unsupported");
        }

        public NdrEmpty ReadEmpty()
        {
            return new NdrEmpty();
        }

        #endregion

        #region Primitive Types

        public byte ReadByte()
        {
            return _reader.ReadByte();
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

        public char ReadChar()
        {
            Align(2);
            return _reader.ReadChar();
        }

        public NdrEnum16 ReadEnum16()
        {
            return ReadInt16();
        }

        #endregion

        #region Fixed Array Types

        public byte[] ReadFixedByteArray(int count)
        {
            byte[] ret = _reader.ReadBytes(count);
            if (ret.Length < count)
            {
                throw new EndOfStreamException();
            }
            return ret;
        }

        public char[] ReadFixedCharArray(int count)
        {
            char[] chars = _reader.ReadChars(count);
            if (chars.Length < count)
            {
                throw new EndOfStreamException();
            }
            return chars;
        }

        public T[] ReadFixedPrimitiveArray<T>(int actual_count) where T : struct
        {
            int size = NdrNativeUtils.GetPrimitiveTypeSize<T>();
            Align(size);
            byte[] total_buffer = ReadFixedByteArray(size * actual_count);
            T[] ret = new T[actual_count];
            Buffer.BlockCopy(total_buffer, 0, ret, 0, total_buffer.Length);
            return ret;
        }

        public T[] ReadFixedArray<T>(Func<T> reader, int actual_count)
        {
            T[] ret = new T[actual_count];
            for (int i = 0; i < actual_count; ++i)
            {
                ret[i] = reader();
            }
            return ret;
        }

        public T[] ReadFixedStructArray<T>(int actual_count) where T : INdrStructure, new()
        {
            return ReadFixedArray(() => ReadStruct<T>(), actual_count);
        }

        #endregion

        #region Conformant Array Types

        public byte[] ReadConformantByteArray()
        {
            int max_count = ReadInt32();
            return ReadFixedByteArray(max_count);
        }

        public char[] ReadConformantCharArray()
        {
            int max_count = ReadInt32();
            return ReadFixedCharArray(max_count);
        }

        public T[] ReadConformantPrimitiveArray<T>() where T : struct
        {
            int max_count = ReadInt32();
            return ReadFixedPrimitiveArray<T>(max_count);
        }

        public T[] ReadConformantArrayCallback<T>(Func<T> reader)
        {
            int max_count = ReadInt32();
            T[] ret = new T[max_count];
            for (int i = 0; i < max_count; ++i)
            {
                ret[i] = reader();
            }
            return ret;
        }

        public T[] ReadConformantStructArray<T>() where T : INdrStructure, new()
        {
            return ReadConformantArrayCallback(() => ReadStruct<T>());
        }

        public string[] ReadConformantStringArray(Func<string> reader)
        {
            return ReadStringArray(ReadConformantArrayCallback(ReadReferent), reader);
        }

        public T[] ReadConformantArray<T>() where T : struct
        {
            if (typeof(T) == typeof(byte))
            {
                return ReadConformantByteArray().Cast<byte, T>();
            }
            else if (typeof(T) == typeof(char))
            {
                return ReadConformantCharArray().Cast<char, T>();
            }
            else if (typeof(T) == typeof(INdrStructure))
            {
                return ReadConformantArrayCallback(() =>
                {
                    T t = new T();
                    ((INdrStructure)t).Unmarshal(this);
                    return t;
                });
            }
            else if (typeof(T).IsPrimitive)
            {
                return ReadConformantPrimitiveArray<T>();
            }
            throw new ArgumentException($"Invalid type {typeof(T)} for {nameof(ReadConformantArray)}");
        }

        #endregion

        #region Varying Array Types

        public byte[] ReadVaryingByteArray()
        {
            int offset = ReadInt32();
            int actual_count = ReadInt32();
            byte[] ret = new byte[offset + actual_count];
            if (_stm.Read(ret, offset, actual_count) != actual_count)
            {
                throw new EndOfStreamException();
            }

            return ret;
        }

        public char[] ReadVaryingCharArray()
        {
            int offset = ReadInt32();
            int actual_count = ReadInt32();
            if (offset == 0)
            {
                return ReadFixedCharArray(actual_count);
            }

            char[] tmp = ReadFixedCharArray(actual_count);
            char[] ret = new char[offset + actual_count];
            Array.Copy(tmp, 0, ret, offset, actual_count);
            return ret;
        }

        public T[] ReadVaryingPrimitiveArray<T>() where T : struct
        {
            int offset = ReadInt32();
            int actual_count = ReadInt32();
            T[] tmp = ReadFixedPrimitiveArray<T>(actual_count);
            T[] ret = new T[offset + actual_count];
            Array.Copy(tmp, 0, ret, offset, actual_count);
            return ret;
        }

        public T[] ReadVaryingArrayCallback<T>(Func<T> reader)
        {
            int offset = ReadInt32();
            int actual_count = ReadInt32();
            T[] ret = new T[offset + actual_count];
            for (int i = 0; i < actual_count; ++i)
            {
                ret[i + offset] = reader();
            }
            return ret;
        }

        public T[] ReadVaryingStructArray<T>() where T : INdrStructure, new()
        {
            return ReadVaryingArrayCallback(() => ReadStruct<T>());
        }

        public string[] ReadVaryingStringArray(Func<string> reader)
        {
            return ReadStringArray(ReadVaryingArrayCallback(ReadReferent), reader);
        }

        public T[] ReadVaryingArray<T>() where T : struct
        {
            if (typeof(T) == typeof(byte))
            {
                return ReadVaryingByteArray().Cast<byte, T>();
            }
            else if (typeof(T) == typeof(char))
            {
                return ReadVaryingCharArray().Cast<char, T>();
            }
            else if (typeof(T) == typeof(INdrStructure))
            {
                return ReadVaryingArrayCallback(() =>
                {
                    T t = new T();
                    ((INdrStructure)t).Unmarshal(this);
                    return t;
                });
            }
            else if (typeof(T).IsPrimitive)
            {
                return ReadVaryingPrimitiveArray<T>();
            }
            throw new ArgumentException($"Invalid type {typeof(T)} for {nameof(ReadVaryingArray)}");
        }

        #endregion

        #region Conformant Varying Array Types

        public byte[] ReadConformantVaryingByteArray()
        {
            int max_count = ReadInt32();
            int offset = ReadInt32();
            int actual_count = ReadInt32();
            byte[] ret = new byte[max_count];
            if (_stm.Read(ret, offset, actual_count) != actual_count)
            {
                throw new EndOfStreamException();
            }

            return ret;
        }

        public char[] ReadConformantVaryingCharArray()
        {
            int max_count = ReadInt32();
            int offset = ReadInt32();
            int actual_count = ReadInt32();

            char[] tmp = ReadFixedCharArray(actual_count);

            if (max_count == actual_count && offset == 0)
            {
                return tmp;
            }

            char[] ret = new char[max_count];
            Array.Copy(tmp, 0, ret, offset, actual_count);
            return ret;
        }

        public T[] ReadConformantVaryingPrimitiveArray<T>() where T : struct
        {
            int max_count = ReadInt32();
            int offset = ReadInt32();
            int actual_count = ReadInt32();

            T[] tmp = ReadFixedPrimitiveArray<T>(actual_count);
            if (max_count == actual_count && offset == 0)
            {
                return tmp;
            }

            T[] ret = new T[max_count];
            Array.Copy(tmp, 0, ret, offset, actual_count);
            return ret;
        }

        public T[] ReadConformantVaryingArrayCallback<T>(Func<T> reader)
        {
            int max_count = ReadInt32();
            int offset = ReadInt32();
            int actual_count = ReadInt32();
            T[] ret = new T[offset + actual_count];
            for (int i = 0; i < actual_count; ++i)
            {
                ret[i + offset] = reader();
            }
            return ret;
        }

        public T[] ReadConformantVaryingStructArray<T>() where T : INdrStructure, new()
        {
            return ReadConformantVaryingArrayCallback(() => ReadStruct<T>());
        }

        public string[] ReadConformantVaryingStringArray(Func<string> reader)
        {
            return ReadStringArray(ReadConformantVaryingArrayCallback(ReadReferent), reader);
        }

        public T[] ReadConformantVaryingArray<T>() where T : struct
        {
            if (typeof(T) == typeof(byte))
            {
                return ReadConformantVaryingByteArray().Cast<byte, T>();
            }
            else if (typeof(T) == typeof(char))
            {
                return ReadConformantVaryingCharArray().Cast<char, T>();
            }
            else if (typeof(T) == typeof(INdrStructure))
            {
                return ReadConformantVaryingArrayCallback(() =>
                {
                    T t = new T();
                    ((INdrStructure)t).Unmarshal(this);
                    return t;
                });
            }
            else if (typeof(T).IsPrimitive)
            {
                return ReadConformantVaryingPrimitiveArray<T>();
            }
            throw new ArgumentException($"Invalid type {typeof(T)} for {nameof(ReadConformantVaryingArray)}");
        }

        #endregion

        #region String Types

        public string ReadFixedString(int count)
        {
            return new string(ReadFixedCharArray(count));
        }

        public string ReadFixedAnsiString(int count)
        {
            return BinaryEncoding.Instance.GetString(ReadFixedByteArray(count));
        }

        public string ReadConformantVaryingAnsiString()
        {
            return BinaryEncoding.Instance.GetString(ReadConformantVaryingByteArray()).TrimEnd('\0');
        }

        public string ReadConformantVaryingString()
        {
            return new string(ReadConformantVaryingCharArray()).TrimEnd('\0');
        }

        #endregion

        #region Pointer Types

        public int ReadReferent()
        {
            // Might need to actually handle referents, guess we'll see.
            return ReadInt32();
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

        public void PopulateDeferredPointers()
        {
            foreach (var a in _deferred_reads)
            {
                a();
            }
            _deferred_reads.Clear();
        }

        #endregion

        #region Structure Types

        public Guid ReadGuid()
        {
            Align(4);
            return new Guid(ReadFixedByteArray(16));
        }

        public T ReadStruct<T>() where T : INdrStructure, new()
        {
            T ret = new T();
            ret.Unmarshal(this);
            return ret;
        }

        #endregion

        #region Dispose Support
        public virtual void Dispose()
        {
            _handles.Dispose();
        }
        #endregion
    }
#pragma warning restore 1591
}
