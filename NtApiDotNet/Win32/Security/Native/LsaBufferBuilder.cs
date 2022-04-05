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
        struct StringEntry
        {
            public FieldInfo field;
            public int position;
            public int length;
        }

        private readonly MemoryStream _stm;
        private readonly BinaryWriter _writer;
        private readonly List<StringEntry> _strs;
        private readonly T _value;
        private static readonly Dictionary<string, FieldInfo> _type_fields = typeof(T).GetFields().ToDictionary(f => f.Name);

        public LsaBufferBuilder(T value)
        {
            _stm = new MemoryStream();
            _writer = new BinaryWriter(_stm);
            _strs = new List<StringEntry>();
            _value = value;
        }

        private int GetCurrentPos()
        {
            return (int)_stm.Position;
        }

        private static FieldInfo GetUnicodeStringField(string name)
        {
            if (!_type_fields.ContainsKey(name))
                throw new ArgumentException($"Unknown field {name}.", nameof(name));
            if (_type_fields[name].FieldType != typeof(UnicodeStringOut))
                throw new ArgumentException($"Invalid field type {_type_fields[name].FieldType}.", nameof(name));
            return _type_fields[name];
        }

        public void AddUnicodeString(string name, byte[] ba)
        {
            if ((ba.Length % 2) != 0)
                throw new ArgumentOutOfRangeException(nameof(ba), "Array must have a two byte aligned length.");
            if (ba == null)
                return;
            int pos = GetCurrentPos();
            _writer.Write(ba);
            _writer.Write((short)0);

            if (ba != null)
            {
                _strs.Add(new StringEntry()
                {
                    position = pos,
                    length = ba.Length,
                    field = GetUnicodeStringField(name)
                });
            }
        }

        public void AddUnicodeString(string name, string str)
        {
            AddUnicodeString(name, str != null ? Encoding.Unicode.GetBytes(str) : null);
        }

        public SafeStructureInOutBuffer<T> ToBuffer()
        {
            byte[] ba = _stm.ToArray();
            using (var buffer = new SafeStructureInOutBuffer<T>(ba.Length, true))
            {
                object obj = _value;
                buffer.Data.WriteBytes(ba);
                foreach (var entry in _strs)
                {
                    UnicodeStringOut str = new UnicodeStringOut
                    {
                        Buffer = buffer.Data.DangerousGetHandle() + entry.position,
                        Length = (ushort)entry.length,
                        MaximumLength = (ushort)(entry.length + 2)
                    };
                    entry.field.SetValue(obj, str);
                }
                buffer.Result = (T)obj;
                return buffer.Detach();
            }
        }
    }
}
