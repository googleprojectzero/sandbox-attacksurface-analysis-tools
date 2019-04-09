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
        #region Private Members
        private readonly MemoryStream _stm;
        private readonly BinaryWriter _writer;
        private readonly List<NtObject> _handles;
        private readonly List<Action> _deferred_writes;
        private int _referent;

        private void WriteEmbeddedPointer<T>(NdrEmbeddedPointer<T> pointer, Action writer)
        {
            WriteReferent(pointer);
            if (pointer != null)
            {
                _deferred_writes.Add(writer);
            }
        }

        #endregion

        #region Constructors
        public NdrMarshalBuffer()
        {
            _stm = new MemoryStream();
            _writer = new BinaryWriter(_stm, Encoding.Unicode);
            _handles = new List<NtObject>();
            _referent = 0x20000;
            _deferred_writes = new List<Action>();
        }
        #endregion

        #region Misc Methods
        public void Align(int alignment)
        {
            byte[] buffer = new byte[NdrNativeUtils.CalculateAlignment((int)_stm.Length, alignment)];
            _stm.Write(buffer, 0, buffer.Length);
        }

        public void WriteSystemHandle<T>(T handle) where T : NtObject
        {
            _handles.Add(handle);
            WriteInt32(_handles.Count);
            if (!NtObjectUtils.IsWindows81OrLess)
            {
                WriteInt32(0);
            }
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
            int alignment = NdrNativeUtils.CalculateAlignment(ret.Length, 8);
            if (alignment > 0)
            {
                Array.Resize(ref ret, ret.Length + alignment);
            }
            return ret;
        }

        #endregion

        #region Primitive Types
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

        #endregion

        #region String Types
        public void WriteTerminatedString(string str)
        {
            WriteConformantVaryingString(str, str.Length + 1);
        }

        public void WriteTerminatedAnsiString(string str)
        {
            WriteConformantVaryingAnsiString(str, str.Length + 1);
        }

        public void WriteConformantVaryingString(string str, long conformance)
        {
            if (str == null)
            {
                return;
            }

            char[] values = (str + '\0').ToCharArray();
            // Maximum count.
            WriteInt32((int)conformance);
            // Offset.
            WriteInt32(0);
            // Actual count.
            WriteInt32(values.Length);
            WriteChars(values);
        }

        public void WriteConformantVaryingAnsiString(string str, long conformance)
        {
            if (str == null)
            {
                return;
            }

            byte[] values = BinaryEncoding.Instance.GetBytes(str + '\0');
            // Maximum count.
            WriteInt32((int)conformance);
            // Offset.
            WriteInt32(0);
            // Actual count.
            WriteInt32(values.Length);
            WriteBytes(values);
        }

        #endregion

        #region Structure Types

        public void WriteGuid(Guid guid)
        {
            Align(4);
            WriteBytes(guid.ToByteArray());
        }

        public void WriteGuid(Guid? guid)
        {
            if (guid.HasValue)
            {
                WriteGuid(guid.Value);
            }
        }

        public void WriteStruct<T>(T structure) where T : INdrStructure
        {
            structure.Marshal(this);
        }

        public void WriteContextHandle(NdrContextHandle handle)
        {
            WriteInt32(handle.Attributes);
            WriteGuid(handle.Uuid);
        }

        #endregion

        #region Pointer Types
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

        public void FlushDeferredWrites()
        {
            foreach (var a in _deferred_writes)
            {
                a();
            }
            _deferred_writes.Clear();
        }

        #endregion

        #region Fixed Array Types
        public void WriteBytes(byte[] array)
        {
            _writer.Write(array);
        }

        public void WriteChars(char[] chars)
        {
            Align(2);
            _writer.Write(chars);
        }

        public void WriteFixedByteArray(byte[] array, int actual_count)
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

        public void WriteFixedPrimitiveArray<T>(T[] array, int actual_count) where T : struct
        {
            int size = NdrNativeUtils.GetPrimitiveTypeSize<T>();
            int actual_size = array.Length * size;
            byte[] total_buffer = new byte[size * actual_count];
            Buffer.BlockCopy(array, 0, total_buffer, 0, Math.Min(actual_count, total_buffer.Length));
            Align(size);
            WriteFixedByteArray(total_buffer, total_buffer.Length);
        }

        public void WriteFixedStructArray<T>(T[] arr, int actual_count) where T : INdrStructure, new()
        {
            for (int i = 0; i < actual_count; ++i)
            {
                if (i < arr.Length)
                {
                    arr[i].Marshal(this);
                }
                else
                {
                    new T().Marshal(this);
                }
            }
        }

        #endregion

        #region Varying Array Types

        public void WriteVaryingByteArray(byte[] array, long variance)
        {
            // Offset.
            WriteInt32(0);
            int var_int = (int)variance;
            // Actual Count
            WriteInt32(var_int);
            Array.Resize(ref array, var_int);
            WriteBytes(array);
        }

        public void WriteVaryingCharArray(char[] array, long variance)
        {
            // Offset.
            WriteInt32(0);
            int var_int = (int)variance;
            // Actual Count
            WriteInt32(var_int);
            Array.Resize(ref array, var_int);
            WriteChars(array);
        }

        public void WriteVaryingPrimitiveArray<T>(T[] array, long variance) where T : struct
        {
            WriteInt32(0);
            int var_int = (int)variance;
            // Actual Count
            WriteInt32(var_int);
            WriteFixedPrimitiveArray<T>(array, var_int);
        }
    
        public void WriteVaryingStructArray<T>(T[] array, long variance) where T : INdrStructure, new()
        {
            WriteVaryingArray(array, t => WriteStruct(t), variance);
        }

        public void WriteVaryingArray<T>(T[] array, Action<T> writer, long variance) where T : new()
        {
            // Offset.
            WriteInt32(0);
            // Actual Count
            WriteInt32((int)variance);
            if (array == null)
            {
                array = new T[0];
            }
            for (int i = 0; i < (int)variance; ++i)
            {
                if (i < array.Length)
                {
                    writer(array[i]);
                }
                else
                {
                    writer(new T());
                }
            }
        }

        #endregion

        #region Conformant Array Types

        public void WriteConformantByteArray(byte[] array, long conformance)
        {
            int var_int = (int)conformance;
            // Max Count
            WriteInt32(var_int);
            Array.Resize(ref array, var_int);
            WriteBytes(array);
        }

        public void WriteConformantCharArray(char[] array, long conformance)
        {
            int var_int = (int)conformance;
            // Max Count
            WriteInt32(var_int);
            Array.Resize(ref array, var_int);
            WriteChars(array);
        }

        public void WriteConformantPrimitiveArray<T>(T[] array, long conformance) where T : struct
        {

            int var_int = (int)conformance;
            // Max Count
            WriteInt32(var_int);
            WriteFixedPrimitiveArray<T>(array, var_int);
        }

        public void WriteConformantStructArray<T>(T[] array, long conformance) where T : INdrStructure, new()
        {
            WriteConformantArray(array, t => WriteStruct(t), conformance);
        }

        public void WriteConformantArray<T>(T[] array, Action<T> writer, long conformance) where T : new()
        {
            // Max Count
            WriteInt32((int)conformance);
            if (array == null)
            {
                array = new T[0];
            }
            for (int i = 0; i < (int)conformance; ++i)
            {
                if (i < array.Length)
                {
                    writer(array[i]);
                }
                else
                {
                    writer(new T());
                }
            }
        }

        #endregion

        #region Conformant Varying Array Types

        public void WriteConformantVaryingByteArray(byte[] array, long conformance, long variance)
        {
            // Max Count
            WriteInt32((int)conformance);
            WriteVaryingByteArray(array, variance);
        }

        public void WriteConformantVaryingCharArray(char[] array, long conformance, long variance)
        {
            // Max Count
            WriteInt32((int)conformance);
            WriteVaryingCharArray(array, variance);
        }

        public void WriteConformantVaryingPrimitiveArray<T>(T[] array, long conformance, long variance) where T : struct
        {
            // Max Count
            WriteInt32((int)conformance);
            WriteVaryingPrimitiveArray(array, variance);
        }

        public void WriteConformantVaryingStructArray<T>(T[] array, long conformance, long variance) where T : INdrStructure, new()
        {
            WriteVaryingArray(array, t => WriteStruct(t), variance);
        }

        public void WriteConformantVaryingArray<T>(T[] array, Action<T> writer, long conformance, long variance) where T : new()
        {
            // Max Count
            WriteInt32((int)conformance);
            WriteVaryingArray(array, writer, variance);
        }

        #endregion

        #region Public Properties
        public List<NtObject> Handles => _handles;
        #endregion
    }
#pragma warning restore 1591
}
