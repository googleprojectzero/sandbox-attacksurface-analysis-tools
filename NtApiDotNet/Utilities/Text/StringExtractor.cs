//  Copyright 2021 Google Inc. All Rights Reserved.
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
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet.Utilities.Text
{
    /// <summary>
    /// Utility class to extract strings from a byte value.
    /// </summary>
    public static class StringExtractor
    {
        private static bool IsPrintable(char c)
        {
            switch (c)
            {
                case '\t':
                case ' ':
                    return true;
            }
            return c > 32 && c < 128;
        }

        private static ExtractedString CreateResult(this StringBuilder builder, long base_offset, long i, ExtractedStringType type, string source)
        {
            int str_length = type.HasFlagSet(ExtractedStringType.Unicode) ? (builder.Length * 2 + 1) : builder.Length;
            return new ExtractedString(builder.ToString(), base_offset + i - str_length, type, source);
        }

        private static IEnumerable<ExtractedString> Extract(Stream data, long base_offset, int minimum_length, ExtractedStringType type, string source)
        {
            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            if (minimum_length <= 0)
                throw new ArgumentException("Must specify a minimum length of at least 1.");

            StringBuilder ascii = new StringBuilder();
            StringBuilder unicode = new StringBuilder();
            StringBuilder unicode_unaligned = new StringBuilder();
            bool parse_ascii = type.HasFlagSet(ExtractedStringType.Ascii);
            bool parse_unicode = type.HasFlagSet(ExtractedStringType.Unicode);
            byte[] unicode_char = new byte[2];
            int b = data.ReadByte();
            long i = 0;
            while(b >= 0)
            {
                if (parse_ascii)
                {
                    char c = (char)b;
                    if (IsPrintable(c))
                    {
                        ascii.Append(c);
                    }
                    else
                    {
                        if (ascii.Length >= minimum_length)
                        {
                            yield return ascii.CreateResult(base_offset, i, ExtractedStringType.Ascii, source);
                        }
                        ascii.Clear();
                    }
                }
                if (parse_unicode)
                {
                    unicode_char[0] = unicode_char[1];
                    unicode_char[1] = (byte)b;
                    char c = BitConverter.ToChar(unicode_char, 0);
                    if ((i & 1) == 1)
                    {
                        if (IsPrintable(c))
                        {
                            unicode.Append(c);
                        }
                        else
                        {
                            if (unicode.Length >= minimum_length)
                            {
                                yield return unicode.CreateResult(base_offset, i, ExtractedStringType.Unicode, source);
                            }
                            unicode.Clear();
                        }
                    }
                    else if (i > 1)
                    {
                        if (IsPrintable(c))
                        {
                            unicode_unaligned.Append(c);
                        }
                        else
                        {
                            if (unicode_unaligned.Length >= minimum_length)
                            {
                                yield return unicode_unaligned.CreateResult(base_offset, i, ExtractedStringType.Unicode, source);
                            }
                            unicode_unaligned.Clear();
                        }
                    }
                }

                i++;
                b = data.ReadByte();
            }

            if (ascii.Length >= minimum_length)
            {
                yield return ascii.CreateResult(base_offset, i, ExtractedStringType.Ascii, source);
            }

            if (unicode.Length >= minimum_length)
            {
                yield return unicode.CreateResult(base_offset, i, ExtractedStringType.Unicode, source);
            }

            if (unicode_unaligned.Length >= minimum_length)
            {
                yield return unicode_unaligned.CreateResult(base_offset, i, ExtractedStringType.Unicode, source);
            }
        }

        /// <summary>
        /// Extracts strings from a binary buffer.
        /// </summary>
        /// <param name="data">The data to search.</param>
        /// <param name="count">The length of the data to search.</param>
        /// <param name="minimum_length">The minimum string length.</param>
        /// <param name="offset">The offset into the data to search.</param>
        /// <param name="type">The type of strings to search for.</param>
        /// <returns>The list of extracted strings.</returns>
        public static IEnumerable<ExtractedString> Extract(byte[] data, int offset, int count, int minimum_length, ExtractedStringType type)
        {
            return Extract(new MemoryStream(data, offset, count), offset, minimum_length, type, string.Empty);
        }

        /// <summary>
        /// Extracts strings from a binary buffer.
        /// </summary>
        /// <param name="data">The data to search.</param>
        /// <param name="minimum_length">The minimum string length.</param>
        /// <param name="type">The type of strings to search for.</param>
        /// <returns>The list of extracted strings.</returns>
        public static IEnumerable<ExtractedString> Extract(byte[] data, int minimum_length, ExtractedStringType type)
        {
            return Extract(data, 0, data.Length, minimum_length, type);
        }

        /// <summary>
        /// Extracts strings from a stream.
        /// </summary>
        /// <param name="stm">The stream to extract strings from.</param>
        /// <param name="minimum_length">The minimum string length.</param>
        /// <param name="type">The type of strings to search for.</param>
        /// <returns>The list of extracted strings.</returns>
        public static IEnumerable<ExtractedString> Extract(Stream stm, int minimum_length, ExtractedStringType type)
        {
            return Extract(stm, 0, minimum_length, type, string.Empty);
        }

        /// <summary>
        /// Extracts strings from a file.
        /// </summary>
        /// <param name="path">The file to search.</param>
        /// <param name="minimum_length">The minimum string length.</param>
        /// <param name="type">The type of strings to search for.</param>
        /// <returns>The list of extracted strings.</returns>
        public static IEnumerable<ExtractedString> Extract(string path, int minimum_length, ExtractedStringType type)
        {
            using (var stm = File.OpenRead(path))
            {
                foreach (var res in Extract(stm, 0, minimum_length, type, stm.Name))
                {
                    yield return res;
                }
            }
        }

        /// <summary>
        /// Extracts strings from a safe buffer.
        /// </summary>
        /// <param name="buffer">Safe buffer to extract the value from.</param>
        /// <param name="minimum_length">The minimum string length.</param>
        /// <param name="type">The type of strings to search for.</param>
        /// <returns>The list of extracted strings.</returns>
        public static IEnumerable<ExtractedString> Extract(SafeBuffer buffer, int minimum_length, ExtractedStringType type)
        {
            return Extract(buffer, 0, buffer.GetLength(), minimum_length, type);
        }

        /// <summary>
        /// Extracts strings from a safe buffer.
        /// </summary>
        /// <param name="buffer">Safe buffer to extract the value from.</param>
        /// <param name="minimum_length">The minimum string length.</param>
        /// <param name="type">The type of strings to search for.</param>
        /// <param name="count">The length of the data to search.</param>
        /// <param name="offset">The offset into the data to search.</param>
        /// <returns>The list of extracted strings.</returns>
        public static IEnumerable<ExtractedString> Extract(SafeBuffer buffer, int offset, int count, int minimum_length, ExtractedStringType type)
        {
            return Extract(new UnmanagedMemoryStream(buffer, offset, count), buffer.DangerousGetHandle().ToInt64() + offset,
                    minimum_length, type, string.Empty);
        }
    }
}
