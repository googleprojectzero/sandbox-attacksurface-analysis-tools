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

    internal abstract class LsaBufferBuilder
    {
        protected struct BufferEntry
        {
            public FieldInfo field;
            public FieldInfo length_field;
            public int position;
            public int length;
            public bool relative;

            public IntPtr GetPointer<U>(SafeStructureInOutBuffer<U> buffer) where U : new()
            {
                if (relative)
                    return new IntPtr(buffer.DataOffset + position);
                return buffer.Data.DangerousGetHandle() + position;
            }
        }

        private readonly MemoryStream _stm;
        private readonly BinaryWriter _writer;
        private readonly List<BufferEntry> _buffers;
        private readonly Dictionary<FieldInfo, LsaBufferBuilder> _sub_builders;
        private readonly object _object;

        private int GetCurrentPos()
        {
            return (int)_stm.Position;
        }

        private void PopulateFields<U>(SafeStructureInOutBuffer<U> buffer) where U : new()
        {
            foreach (var pair in _sub_builders)
            {
                var builder = pair.Value;
                builder.PopulateFields(buffer);
                pair.Key.SetValue(_object, builder._object);
            }

            foreach (var entry in _buffers)
            {
                if (entry.field.FieldType == typeof(UnicodeStringOut))
                {
                    UnicodeStringOut str = new UnicodeStringOut
                    {
                        Buffer = entry.GetPointer(buffer),
                        Length = (ushort)entry.length,
                        MaximumLength = (ushort)(entry.length + 2)
                    };
                    entry.field.SetValue(_object, str);
                }
                else if (entry.field.FieldType == typeof(IntPtr))
                {
                    entry.field.SetValue(_object, entry.GetPointer(buffer));
                    entry.length_field.SetValue(_object, entry.length);
                }
            }
        }

        protected SafeStructureInOutBuffer<U> ToBuffer<U>() where U : new()
        {
            byte[] ba = _stm.ToArray();
            using (var buffer = new SafeStructureInOutBuffer<U>(ba.Length, true))
            {
                buffer.Data.WriteBytes(ba);
                PopulateFields(buffer);
                buffer.Result = (U)_object;
                return buffer.Detach();
            }
        }

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

        private protected LsaBufferBuilder(object obj, LsaBufferBuilder parent)
        {
            _stm = parent?._stm ?? new MemoryStream();
            _writer = parent?._writer ?? new BinaryWriter(_stm);
            _buffers = new List<BufferEntry>();
            _object = obj;
            _sub_builders = new Dictionary<FieldInfo, LsaBufferBuilder>();
        }

        protected abstract FieldInfo GetField<U>(string name);

        private FieldInfo GetUnicodeStringField(string name) => GetField<UnicodeStringOut>(name);
        private FieldInfo GetIntPtrField(string name) => GetField<IntPtr>(name);
        private FieldInfo GetInt32Field(string name) => GetField<int>(name);

        public void AddUnicodeString(string name, byte[] ba, bool relative = false)
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
                    field = GetUnicodeStringField(name),
                    relative = relative
                });
            }
        }

        public void AddUnicodeString(string name, SecureString str, bool relative = false)
        {
            AddUnicodeString(name, GetSecureStringBytes(str), relative);
        }

        public void AddUnicodeString(string name, string str, bool relative = false)
        {
            AddUnicodeString(name, str != null ? Encoding.Unicode.GetBytes(str) : null, relative);
        }

        public void AddPointerBuffer(string ptr_name, string length_name, byte[] buffer, bool relative = false)
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
                length_field = GetInt32Field(length_name),
                relative = relative
            });
        }

        public LsaBufferBuilder<U> GetSubBuilder<U>(string name) where U : new()
        {
            FieldInfo field = GetField<U>(name);
            if (_sub_builders.ContainsKey(field))
                return (LsaBufferBuilder<U>)_sub_builders[field];

            object obj = field.GetValue(_object);
            var builder = new LsaBufferBuilder<U>(obj, this);
            _sub_builders[field] = builder;
            return builder;
        }
    }

    internal class LsaBufferBuilder<T> : LsaBufferBuilder where T : new()
    {
        private static readonly Dictionary<string, FieldInfo> _type_fields = typeof(T).GetFields().ToDictionary(f => f.Name);

        public LsaBufferBuilder(object value, LsaBufferBuilder parent) 
            : base(value, parent)
        {
        }

        public LsaBufferBuilder(T value) : base(value, null)
        {
        }

        public SafeStructureInOutBuffer<T> ToBuffer()
        {
            return ToBuffer<T>();
        }

        protected override FieldInfo GetField<U>(string name)
        {
            if (!_type_fields.ContainsKey(name))
                throw new ArgumentException($"Unknown field {name}.", nameof(name));
            if (_type_fields[name].FieldType != typeof(U))
                throw new ArgumentException($"Invalid field type {_type_fields[name].FieldType}.", nameof(name));
            return _type_fields[name];
        }
    }
}
