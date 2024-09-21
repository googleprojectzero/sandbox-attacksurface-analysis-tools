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

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace NtCoreLib.Utilities.Text;

/// <summary>
/// Class to build a hex dump from a stream of bytes.
/// </summary>
public sealed class HexDumpBuilder
{
    #region Private Members
    private readonly Stream _data = null;
    private readonly bool _can_write;
    private readonly StringBuilder _builder = new();
    private readonly bool _print_address;
    private readonly bool _print_ascii;
    private readonly bool _hide_repeating;
    private readonly long _address_offset;
    private const int CHUNK_LIMIT = 256;
    private byte[] _last_line = null;
    private int _repeat_count = 0;

    private int GetDataLeft()
    {
        return (int)(_data.Length - _data.Position);
    }

    private bool IsRepeatingLine(byte[] line)
    {
        if (!_hide_repeating)
            return false;
        byte[] last_line = _last_line;
        _last_line = line;
        if (last_line == null)
        {
            return false;
        }
        if (last_line.Length != line.Length)
        {
            return false;
        }

        for (int i = 0; i < last_line.Length; ++i)
        {
            if (last_line[i] != line[i])
                return false;
        }
        return true;
    }

    private void AppendChunks()
    {
        while (GetDataLeft() >= 16)
        {
            long curr_pos = _data.Position + _address_offset;
            byte[] line = new byte[16];
            _data.Read(line, 0, 16);

            if (IsRepeatingLine(line))
            {
                _repeat_count++;
                continue;
            }
            else if(_repeat_count > 0)
            {
                _builder.AppendLine($"-> REPEATED {_repeat_count} LINES");
                _repeat_count = 0;
            }

            if (_print_address)
            {
                if (curr_pos < uint.MaxValue)
                {
                    _builder.AppendFormat("{0:X08}: ", curr_pos);
                }
                else
                {
                    _builder.AppendFormat("{0:X016}: ", curr_pos);
                }
            }
            for (int j = 0; j < 16; ++j)
            {
                _builder.AppendFormat("{0:X02} ", line[j]);
            }

            if (_print_ascii)
            {
                _builder.Append(" - ");
                for (int j = 0; j < 16; ++j)
                {
                    byte b = line[j];
                    char c = b >= 32 && b < 127 ? (char)b : '.';
                    _builder.Append(c);
                }
            }
            _builder.AppendLine();
        }
    }

    private void AppendTrailing()
    {
        int line_length = GetDataLeft();
        System.Diagnostics.Debug.Assert(line_length < 16);

        if (_repeat_count > 0)
        {
            _builder.AppendLine($"-> REPEATED {_repeat_count} LINES");
        }

        if (line_length == 0)
        {
            return;
        }

        int j = 0;
        if (_print_address)
        {
            long address = _data.Position + _address_offset;
            if (address < uint.MaxValue)
            {
                _builder.AppendFormat("{0:X08}: ", address);
            }
            else
            {
                _builder.AppendFormat("{0:X016}: ", address);
            }
        }

        byte[] line = new byte[line_length];
        _data.Read(line, 0, line.Length);

        for (; j < line_length; ++j)
        {
            _builder.AppendFormat("{0:X02} ", line[j]);
        }
        for (; j < 16; ++j)
        {
            _builder.Append("   ");
        }
        if (_print_ascii)
        {
            _builder.Append(" - ");
            for (j = 0; j < line_length; ++j)
            {
                byte b = line[j];
                char c = b >= 32 && b < 127 ? (char)b : '.';
                _builder.Append(c);
            }
        }
        _builder.AppendLine();
    }

    private static int GetHexValue(char c)
    {
        if (c >= '0' && c <= '9')
        {
            return c - '0';
        }
        else if (c >= 'a' && c <= 'f')
        {
            return (c - 'a') + 10;
        }
        else if (c >= 'A' && c <= 'F')
        {
            return (c - 'A') + 10;
        }
        throw new FormatException($"Invalid hex character {c}.");
    }
    #endregion

    #region Public Methods
    /// <summary>
    /// Append an array of bytes to the hex dump.
    /// </summary>
    /// <param name="ba">The byte array.</param>
    /// <param name="length">The length of the bytes to append from the array.</param>
    /// <param name="offset">The start offset in the bytes to append.</param>
    public void Append(byte[] ba, int offset, int length)
    {
        if (!_can_write)
            throw new InvalidOperationException();
        long curr_pos = _data.Position;
        _data.Position = _data.Length;
        _data.Write(ba, offset, length);
        _data.Position = curr_pos;
        if (GetDataLeft() >= CHUNK_LIMIT)
        {
            AppendChunks();
        }
    }

    /// <summary>
    /// Append an array of bytes to the hex dump.
    /// </summary>
    /// <param name="ba">The byte array.</param>
    public void Append(byte[] ba)
    {
        Append(ba, 0, ba.Length);
    }

    /// <summary>
    /// Append a file or part of a file.
    /// </summary>
    /// <param name="path">The path to the file.</param>
    /// <param name="length">The length of the file to append. If 0 will append all remaining data.</param>
    /// <param name="offset">The start offset in the file to append.</param>
    public void AppendFile(string path, long offset, long length)
    {
        using var fs = File.OpenRead(path);
        fs.Position = offset;
        long remaining = length;
        if (remaining == 0)
        {
            remaining = fs.Length - offset;
        }

        byte[] chunk = new byte[64 * 1024];
        while (remaining > 0)
        {
            int read_length = fs.Read(chunk, 0, (int)Math.Min(chunk.Length, remaining));
            if (read_length == 0)
            {
                break;
            }
            Append(chunk, 0, read_length);
            remaining -= read_length;
        }
    }

    /// <summary>
    /// Append a file or part of a file.
    /// </summary>
    /// <param name="path">The path to the file.</param>
    public void AppendFile(string path)
    {
        AppendFile(path, 0, 0);
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
    #endregion

    #region Constructors
    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="print_header">Print a header.</param>
    /// <param name="print_address">Print the address.</param>
    /// <param name="print_ascii">Print the ASCII text.</param>
    /// <param name="hide_repeating">Hide repeating lines.</param>
    /// <param name="address_offset">Offset for address printing.</param>
    public HexDumpBuilder(bool print_header = false, bool print_address = false, bool print_ascii = false, bool hide_repeating = false, long address_offset = 0) 
        : this(new MemoryStream(), print_header, print_address, print_ascii, hide_repeating, address_offset)
    {
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="buffer">The safe buffer to print.</param>
    /// <param name="length">The length to display.</param>
    /// <param name="offset">The offset into the buffer to display.</param>
    /// <param name="print_header">Print a header.</param>
    /// <param name="print_address">Print the address.</param>
    /// <param name="print_ascii">Print the ASCII text.</param>
    /// <param name="hide_repeating">Hide repeating lines.</param>
    public HexDumpBuilder(SafeBuffer buffer, long offset, long length, bool print_header = false, bool print_address = false, bool print_ascii = false, bool hide_repeating = false)
        : this(new UnmanagedMemoryStream(buffer, offset, length == 0 ? (long)buffer.ByteLength : length), 
              print_header, print_address, print_ascii, hide_repeating, buffer.DangerousGetHandle().ToInt64())
    {
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="buffer">The safe buffer to print.</param>
    /// <param name="print_header">Print a header.</param>
    /// <param name="print_address">Print the address.</param>
    /// <param name="print_ascii">Print the ASCII text.</param>
    /// <param name="hide_repeating">Hide repeating lines.</param>
    public HexDumpBuilder(SafeBuffer buffer, bool print_header = false, bool print_address = false, bool print_ascii = false, bool hide_repeating = false)
        : this(buffer, 0, (long)buffer.ByteLength, print_header, print_address, print_ascii, hide_repeating)
    {
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="stm">The stream to print.</param>
    /// <param name="print_header">Print a header.</param>
    /// <param name="print_address">Print the address.</param>
    /// <param name="print_ascii">Print the ASCII text.</param>
    /// <param name="hide_repeating">Hide repeating lines.</param>
    /// <param name="address_offset">Offset for address printing.</param>
    public HexDumpBuilder(Stream stm, bool print_header = false, bool print_address = false, bool print_ascii = false, bool hide_repeating = false, long address_offset = 0)
    {
        _address_offset = address_offset;
        _data = stm;
        _can_write = _data.CanSeek && _data.CanWrite;
        _print_address = print_address;
        _print_ascii = print_ascii;
        _hide_repeating = hide_repeating;
        if (print_header)
        {
            if (print_address)
            {
                if (address_offset > uint.MaxValue)
                {
                    _builder.Append(' ', 18);
                }
                else
                {
                    _builder.Append(' ', 10);
                }
            }

            _builder.Append("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F ");
            if (print_ascii)
            {
                _builder.AppendLine(" - 0123456789ABCDEF");
            }
            else
            {
                _builder.AppendLine();
            }
            int dash_count = 48;
            if (print_address)
            {
                if (address_offset > uint.MaxValue)
                {
                    dash_count += 18;
                }
                else
                {
                    dash_count += 10;
                }
            }
            if (print_ascii)
            {
                dash_count += 19;
            }
            _builder.Append('-', dash_count);
            _builder.AppendLine();
        }
    }
    #endregion

    #region Static Members
    /// <summary>
    /// Parse a hex dump into a byte array.
    /// </summary>
    /// <param name="str">The hex string. Can contain non-hex characters.</param>
    /// <returns>The parsed string as a byte array.</returns>
    /// <remarks>This won't necessarily parse correctly an arbitary hex dump, but it will if you just use the hex of the bytes.</remarks>
    public static byte[] ParseHexDump(string str)
    {
        if (str.Length == 0)
            return new byte[0];
        Regex re = new("[^a-fA-F0-9]*", RegexOptions.Multiline);
        str = re.Replace(str, "");
        if ((str.Length & 1) != 0)
        {
            throw new FormatException("Invalid hex string length. Must be a multiple of 2.");
        }

        byte[] ret = new byte[str.Length / 2];
        for (int i = 0; i < ret.Length; ++i)
        {
            ret[i] = (byte)((GetHexValue(str[i * 2]) << 4) | GetHexValue(str[i * 2 + 1]));
        }
        return ret;
    }

    /// <summary>
    /// Parse a hex string into a byte array.
    /// </summary>
    /// <param name="str">The hex string. Can contain non-hex characters.</param>
    /// <param name="data">The parsed string as a byte array.</param>
    /// <returns>True if the parse was successful.</returns>
    /// <remarks>This won't necessarily parse correctly an arbitary hex dump, but it will if you just use the hex of the bytes.</remarks>
    public static bool TryParseHexDump(string str, out byte[] data)
    {
        data = null;
        try
        {
            data = ParseHexDump(str);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>
    /// Convert a buffer to a string.
    /// </summary>
    /// <param name="buffer">The buffer to convert.</param>
    /// <param name="print_header">Print a header.</param>
    /// <param name="print_address">Print the address.</param>
    /// <param name="print_ascii">Print the ASCII text.</param>
    /// <param name="hide_repeating">Hide repeating lines.</param>
    /// <param name="address_offset">Offset for address printing.</param>
    /// <returns>The buffer as a string.</returns>
    public static string ToHexDump(byte[] buffer, bool print_header = false, bool print_address = false, 
        bool print_ascii = false, bool hide_repeating = false, long address_offset = 0)
    {
        var builder = new HexDumpBuilder(print_header, print_address, print_ascii, hide_repeating, address_offset);
        builder.Append(buffer);
        builder.Complete();
        return builder.ToString();
    }
    #endregion
}
