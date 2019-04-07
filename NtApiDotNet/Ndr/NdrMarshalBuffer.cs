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

        public void Write(byte b)
        {
            _writer.Write(b);
        }

        public void Write(sbyte b)
        {
            _writer.Write(b);
        }

        public void Write(short s)
        {
            Align(2);
            _writer.Write(s);
        }

        public void Write(ushort s)
        {
            Align(2);
            _writer.Write(s);
        }

        public void Write(int i)
        {
            Align(4);
            _writer.Write(i);
        }

        public void Write(uint i)
        {
            Align(4);
            _writer.Write(i);
        }

        public void Write(long l)
        {
            Align(8);
            _writer.Write(l);
        }

        public void Write(ulong l)
        {
            Align(8);
            _writer.Write(l);
        }

        public void Write(float f)
        {
            Align(4);
            _writer.Write(f);
        }

        public void Write(double d)
        {
            Align(8);
            _writer.Write(d);
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

        public void Write(NdrInt3264 p)
        {
            Write(p.Value);
        }

        public void Write(NdrUInt3264 p)
        {
            Write(p.Value);
        }

        public void WriteSystemHandle(NtObject handle)
        {
            _handles.Add(handle);
            Write(_handles.Count);
            if (!NtObjectUtils.IsWindows81OrLess)
            {
                Write(0);
            }
        }

        public void WriteReferent<T>(T obj) where T : class
        {
            if (obj == null)
            {
                Write(0);
            }
            else
            {
                Write(_referent);
                _referent += 4;
            }
        }

        public void WriteReferent<T>(T? obj) where T : struct
        {
            if (!obj.HasValue)
            {
                Write(0);
            }
            else
            {
                Write(_referent++);
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
            Write(values.Length);
            // Offset.
            Write(0);
            // Actual count.
            Write(values.Length);
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
            Write(values.Length);
            // Offset.
            Write(0);
            // Actual count.
            Write(values.Length);
            Write(values);
        }

        public void WriteGuid(Guid guid)
        {
            Align(4);
            Write(guid.ToByteArray());
        }

        public void WriteStruct(INdrStructure structure)
        {
            structure.Marshal(this);
        }

        public void Write<T>(T? value) where T : struct
        {
            if (value.HasValue)
            {
                object v = value.Value;
                if (v is byte b)
                {
                    Write(b);
                }
                else if (v is short s)
                {
                    Write(s);
                }
                else if (v is int i)
                {
                    Write(i);
                }
                else if (v is long l)
                {
                    Write(l);
                }
                if (v is sbyte sb)
                {
                    Write(sb);
                }
                else if (v is ushort us)
                {
                    Write(us);
                }
                else if (v is uint ui)
                {
                    Write(ui);
                }
                else if (v is ulong ul)
                {
                    Write(ul);
                }
                else if (v is Guid g)
                {
                    WriteGuid(g);
                }
                else if (v is NdrInt3264 ni)
                {
                    Write(ni);
                }
                else if (v is NdrUInt3264 nu)
                {
                    Write(nu);
                }
                else if (v is INdrStructure st)
                {
                    WriteStruct(st);
                }

                throw new ArgumentException($"Unexpected type {v.GetType()}");
            }
        }

        public void WriteContextHandle(NdrContextHandle handle)
        {
            Write(handle.Attributes);
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
