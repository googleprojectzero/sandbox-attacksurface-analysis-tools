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
        }

        public void Align(int alignment)
        {
            _stm.Position += CalculateAlignment((int)_stm.Length, alignment);
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

        public void Write<T>(T[] arr) where T : INdrStructure
        {
            foreach (var v in arr)
            {
                v.Marshal(this);
            }
        }

        public void Write(IntPtr p)
        {
            Write(p.ToInt32());
        }

        public void Write(UIntPtr p)
        {
            Write(p.ToUInt32());
        }

        public void Write(NtObject handle)
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

        public void Write(Guid guid)
        {
            Align(4);
            Write(guid.ToByteArray());
        }

        public void Write(INdrStructure structure)
        {
            structure.Marshal(this);
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
