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

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace NtApiDotNet.Win32.Security.Native
{
    internal static class LsaBufferBuilderUtils
    {
        public static LsaBufferBuilder<T> ToBuilder<T>(this T value) where T : new()
        {
            return new LsaBufferBuilder<T>(value);
        }
    }

    internal class LsaBufferBuilder<T> where T : new()
    {
        struct BufferEntry
        {
            public FieldInfo field;
            public FieldInfo length_field;
            public int position;
            public int length;
        }

        private readonly MemoryStream _stm;
        private readonly BinaryWriter _writer;
        private readonly List<BufferEntry> _buffers;
        private readonly T _value;
        private static readonly Dictionary<string, FieldInfo> _type_fields = typeof(T).GetFields().ToDictionary(f => f.Name);

        private static byte[] GetSecureStringBytes(SecureString str)
        {
            if (str == null)
                return null;
            using (var buffer = new SecureStringMarshalBuffer(str))
            {
                byte[] ret = new byte[str.Length * 2];
                Marshal.Copy(buffer.Ptr, ret, 0, ret.Length);
                return ret;
            }
        }

        public LsaBufferBuilder(T value)
        {
            _stm = new MemoryStream();
            _writer = new BinaryWriter(_stm);
            _buffers = new List<BufferEntry>();
            _value = value;
        }

        private int GetCurrentPos()
        {
            return (int)_stm.Position;
        }

        private static FieldInfo GetField<U>(string name)
        {
            if (!_type_fields.ContainsKey(name))
                throw new ArgumentException($"Unknown field {name}.", nameof(name));
            if (_type_fields[name].FieldType != typeof(U))
                throw new ArgumentException($"Invalid field type {_type_fields[name].FieldType}.", nameof(name));
            return _type_fields[name];
        }

        private static FieldInfo GetUnicodeStringField(string name) => GetField<UnicodeStringOut>(name);
        private static FieldInfo GetIntPtrField(string name) => GetField<IntPtr>(name);
        private static FieldInfo GetInt32Field(string name) => GetField<int>(name);

        public void AddUnicodeString(string name, byte[] ba)
        {
            if (ba == null)
                return;
            if ((ba.Length % 2) != 0)
                throw new ArgumentOutOfRangeException(nameof(ba), "Array must have a two byte aligned length.");
            int pos = GetCurrentPos();
            _writer.Write(ba);
            _writer.Write((short)0);

            if (ba != null)
            {
                _buffers.Add(new BufferEntry()
                {
                    position = pos,
                    length = ba.Length,
                    field = GetUnicodeStringField(name)
                });
            }
        }

        public void AddUnicodeString(string name, SecureString str)
        {
            AddUnicodeString(name, GetSecureStringBytes(str));
        }

        public void AddUnicodeString(string name, string str)
        {
            AddUnicodeString(name, str != null ? Encoding.Unicode.GetBytes(str) : null);
        }

        public void AddPointerBuffer(string ptr_name, string length_name, byte[] buffer)
        {
            if (buffer == null)
                return;
            int pos = GetCurrentPos();
            _writer.Write(buffer);
            _buffers.Add(new BufferEntry()
            {
                position = pos,
                length = buffer.Length,
                field = GetIntPtrField(ptr_name),
                length_field = GetInt32Field(length_name)
            });
        }

        public SafeStructureInOutBuffer<T> ToBuffer()
        {
            byte[] ba = _stm.ToArray();
            using (var buffer = new SafeStructureInOutBuffer<T>(ba.Length, true))
            {
                object obj = _value;
                buffer.Data.WriteBytes(ba);
                foreach (var entry in _buffers)
                {
                    if (entry.field.FieldType == typeof(UnicodeStringOut))
                    {
                        UnicodeStringOut str = new UnicodeStringOut
                        {
                            Buffer = buffer.Data.DangerousGetHandle() + entry.position,
                            Length = (ushort)entry.length,
                            MaximumLength = (ushort)(entry.length + 2)
                        };
                        entry.field.SetValue(obj, str);
                    }
                    else if (entry.field.FieldType == typeof(IntPtr))
                    {
                        IntPtr ptr = buffer.Data.DangerousGetHandle() + entry.position;
                        entry.field.SetValue(obj, ptr);
                        entry.length_field.SetValue(obj, entry.length);
                    }
                }
                buffer.Result = (T)obj;
                return buffer.Detach();
            }
        }
    }
}
