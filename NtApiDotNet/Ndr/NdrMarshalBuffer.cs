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
    /// A buffer to marshal NDR data to.
    /// </summary>
    /// <remarks>This class is primarily for internal use only.</remarks>
    public class NdrMarshalBuffer
    {
        private readonly MemoryStream _stm;
        private readonly BinaryWriter _writer;
        private readonly List<NtObject> _handles;
        private readonly List<Action> _deferred_writes;
        private int _referent;

        private static int CalculateAlignment(int offset, int alignment)
        {
            int result = alignment - (offset % alignment);
            if (result < alignment)
            {
                return result;
            }
            return 0;
        }

        public NdrMarshalBuffer()
        {
            _stm = new MemoryStream();
            _writer = new BinaryWriter(_stm, Encoding.Unicode);
            _handles = new List<NtObject>();
            _referent = 0x20000;
            _deferred_writes = new List<Action>();
        }

        public void Align(int alignment)
        {
            byte[] buffer = new byte[CalculateAlignment((int)_stm.Length, alignment)];
            _stm.Write(buffer, 0, buffer.Length);
        }

        public void WriteByte(byte b)
        {
            _writer.Write(b);
        }

        public void WriteByte(byte? b)
        {
            if (b.HasValue)
            {
                WriteByte(b.Value);
            }
        }

        public void WriteSByte(sbyte b)
        {
            _writer.Write(b);
        }

        public void WriteSByte(sbyte? b)
        {
            if (b.HasValue)
            {
                WriteSByte(b.Value);
            }
        }

        public void WriteInt16(short s)
        {
            Align(2);
            _writer.Write(s);
        }

        public void WriteInt16(short? s)
        {
            if (s.HasValue)
            {
                WriteInt16(s.Value);
            }
        }

        public void WriteUInt16(ushort s)
        {
            Align(2);
            _writer.Write(s);
        }

        public void WriteUInt16(ushort? s)
        {
            if (s.HasValue)
            {
                WriteUInt16(s.Value);
            }
        }

        public void WriteInt32(int i)
        {
            Align(4);
            _writer.Write(i);
        }

        public void WriteInt32(int? i)
        {
            if (i.HasValue)
            {
                WriteInt32(i.Value);
            }
        }

        public void WriteUInt32(uint i)
        {
            Align(4);
            _writer.Write(i);
        }

        public void WriteUInt32(uint? i)
        {
            if (i.HasValue)
            {
                WriteUInt32(i.Value);
            }
        }

        public void WriteInt64(long l)
        {
            Align(8);
            _writer.Write(l);
        }

        public void WriteInt64(long? l)
        {
            if (l.HasValue)
            {
                WriteInt64(l.Value);
            }
        }

        public void WriteUInt64(ulong l)
        {
            Align(8);
            _writer.Write(l);
        }

        public void WriteUInt64(ulong? l)
        {
            if (l.HasValue)
            {
                WriteUInt64(l.Value);
            }
        }

        public void WriteFloat(float f)
        {
            Align(4);
            _writer.Write(f);
        }

        public void WriteFloat(float? f)
        {
            if (f.HasValue)
            {
                WriteFloat(f.Value);
            }
        }

        public void WriteDouble(double d)
        {
            Align(8);
            _writer.Write(d);
        }

        public void WriteDouble(double? d)
        {
            if (d.HasValue)
            {
                WriteDouble(d.Value);
            }
        }

        public void WriteChar(char c)
        {
            Align(2);
            _writer.Write(c);
        }

        public void WriteChar(char? c)
        {
            if (c.HasValue)
            {
                WriteChar(c.Value);
            }
        }

        public void Write(byte[] array)
        {
            _writer.Write(array);
        }

        public void Write(char[] chars)
        {
            Align(2);
            _writer.Write(chars);
        }

        public void WriteFixedBytes(byte[] array, int actual_count)
        {
            if (array.Length != actual_count)
            {
                array = (byte[])array.Clone();
                Array.Resize(ref array, actual_count);
            }
            _writer.Write(array);
        }

        public void WriteFixedChars(char[] chars, int actual_count)
        {
            Align(2);
            if (chars.Length != actual_count)
            {
                chars = (char[])chars.Clone();
                Array.Resize(ref chars, actual_count);
            }
            _writer.Write(chars);
        }

        public void WriteFixedString(string str, int actual_count)
        {
            WriteFixedChars(str.ToCharArray(), actual_count);
        }

        public void WriteArray<T>(T[] arr) where T : INdrStructure
        {
            foreach (var v in arr)
            {
                v.Marshal(this);
            }
        }

        public void WriteInt3264(NdrInt3264 p)
        {
            WriteInt32(p.Value);
        }

        public void WriteInt3264(NdrInt3264? p)
        {
            if (p.HasValue)
            {
                WriteInt3264(p.Value);
            }
        }

        public void WriteUInt3264(NdrUInt3264 p)
        {
            WriteUInt32(p.Value);
        }

        public void WriteUInt3264(NdrUInt3264? p)
        {
            if (p.HasValue)
            {
                WriteUInt3264(p.Value);
            }
        }

        public void WriteSystemHandle(NtObject handle)
        {
            _handles.Add(handle);
            WriteInt32(_handles.Count);
            if (!NtObjectUtils.IsWindows81OrLess)
            {
                WriteInt32(0);
            }
        }

        public void WriteReferent<T>(T obj) where T : class
        {
            if (obj == null)
            {
                WriteInt32(0);
            }
            else
            {
                WriteInt32(_referent);
                _referent += 4;
            }
        }

        public void WriteReferent<T>(T? obj) where T : struct
        {
            if (!obj.HasValue)
            {
                WriteInt32(0);
            }
            else
            {
                WriteInt32(_referent++);
            }
        }

        public void WriteConformantString(string str)
        {
            if (str == null)
            {
                return;
            }
            char[] values = (str + '\0').ToCharArray();
            // Maximum count.
            WriteInt32(values.Length);
            // Offset.
            WriteInt32(0);
            // Actual count.
            WriteInt32(values.Length);
            Write(values);
        }

        public void WriteAnsiConformantString(string str)
        {
            if (str == null)
            {
                return;
            }

            byte[] values = BinaryEncoding.Instance.GetBytes(str + '\0');
            // Maximum count.
            WriteInt32(values.Length);
            // Offset.
            WriteInt32(0);
            // Actual count.
            WriteInt32(values.Length);
            Write(values);
        }

        public void WriteGuid(Guid guid)
        {
            Align(4);
            Write(guid.ToByteArray());
        }

        public void WriteGuid(Guid? guid)
        {
            if (guid.HasValue)
            {
                WriteGuid(guid.Value);
            }
        }

        public void WriteStruct(INdrStructure structure)
        {
            structure.Marshal(this);
        }

        public void WriteContextHandle(NdrContextHandle handle)
        {
            WriteInt32(handle.Attributes);
            WriteGuid(handle.Uuid);
        }

        private void WriteEmbeddedPointer<T>(NdrEmbeddedPointer<T> pointer, Action writer)
        {
            WriteReferent(pointer);
            if (pointer != null)
            {
                _deferred_writes.Add(writer);
            }
        }

        public void WriteEmbeddedPointer<T>(NdrEmbeddedPointer<T> pointer, Action<T> writer)
        {
            WriteEmbeddedPointer(pointer, () => writer(pointer));
        }

        public void WriteEmbeddedPointer<T, U>(NdrEmbeddedPointer<T> pointer, Action<T, U> writer, U arg)
        {
            WriteEmbeddedPointer(pointer, () => writer(pointer, arg));
        }

        public void WriteEmbeddedPointer<T, U, V>(NdrEmbeddedPointer<T> pointer, Action<T, U, V> writer, U arg, V arg2)
        {
            WriteEmbeddedPointer(pointer, () => writer(pointer, arg, arg2));
        }

        public void WriteEmbeddedStructPointer<T>(NdrEmbeddedPointer<T> pointer) where T : INdrStructure, new()
        {
            WriteEmbeddedPointer(pointer, () => WriteStruct((T)pointer));
        }

        public void FlushDeferredWrites()
        {
            foreach (var a in _deferred_writes)
            {
                a();
            }
            _deferred_writes.Clear();
        }

        public void WriteUnsupported(NdrUnsupported type, string name)
        {
            throw new NotImplementedException($"Writing type {name} is unsupported");
        }

        public void CheckNull<T>(T obj, string name) where T : class
        {
            if (obj == null)
            {
                throw new ArgumentNullException(name);
            }
        }

        public byte[] ToArray()
        {
            byte[] ret = _stm.ToArray();
            int alignment = CalculateAlignment(ret.Length, 8);
            if (alignment > 0)
            {
                Array.Resize(ref ret, ret.Length + alignment);
            }
            return ret;
        }

        internal List<NtObject> Handles => _handles;
    }
#pragma warning restore 1591
}
