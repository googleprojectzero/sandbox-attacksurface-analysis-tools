//  Copyright 2020 Google Inc. All Rights Reserved.
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

using System.Collections.Generic;
using System.Text;

namespace NtApiDotNet.Utilities.Text
{
    /// <summary>
    /// Class to build a hex dump from a stream of bytes.
    /// </summary>
    public sealed class HexDumpBuilder
    {
        private readonly List<byte> _data = new List<byte>();
        private readonly StringBuilder _builder = new StringBuilder();
        private long _current_offset = 0;
        private const int CHUNK_LIMIT = 256;

        private void AppendChunks()
        {
            int total_count = _data.Count / 16;
            for (int i = 0; i < total_count; ++i)
            {
                _builder.AppendFormat("{0:X08}: ", _current_offset);
                _current_offset += 16;
                int index = i * 16;
                for (int j = 0; j < 16; ++j)
                {
                    _builder.AppendFormat("{0:X02} ", _data[index + j]);
                }
                _builder.Append(" - ");
                for (int j = 0; j < 16; ++j)
                {
                    byte b = _data[index + j];
                    char c = b >= 32 && b < 127 ? (char)b : '.';
                    _builder.Append(c);
                }
                _builder.AppendLine();
            }
            _data.RemoveRange(0, total_count * 16);
        }

        private void AppendTrailing()
        {
            System.Diagnostics.Debug.Assert(_data.Count < 16);
            int line_length = _data.Count;
            int j = 0;
            _builder.AppendFormat("{0:X08}: ", _current_offset);
            for (; j < line_length; ++j)
            {
                _builder.AppendFormat("{0:X02} ", _data[j]);
            }
            for (; j < 16; ++j)
            {
                _builder.Append("   ");
            }
            _builder.Append(" - ");
            for (j = 0; j < line_length; ++j)
            {
                byte b = _data[j];
                char c = b >= 32 && b < 127 ? (char)b : '.';
                _builder.Append(c);
            }
            _builder.AppendLine();
        }

        /// <summary>
        /// Append an array of bytes to the hex dump.
        /// </summary>
        /// <param name="ba">The byte array.</param>
        public void Append(byte[] ba)
        {
            _data.AddRange(ba);
            if (_data.Count >= CHUNK_LIMIT)
            {
                AppendChunks();
            }
        }

        /// <summary>
        /// Complete the hex dump string.
        /// </summary>
        public void Complete()
        {
            AppendChunks();
            AppendTrailing();
        }

        /// <summary>
        /// Finish builder and convert to a string.
        /// </summary>
        /// <returns>The hex dump.</returns>
        public override string ToString()
        {
            return _builder.ToString();
        }
    }
}
