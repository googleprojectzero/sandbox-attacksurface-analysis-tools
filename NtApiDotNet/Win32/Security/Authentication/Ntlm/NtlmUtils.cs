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

using NtApiDotNet.Utilities.Text;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Ntlm
{
    internal static class NtlmUtils
    {
        internal static bool TryParseStringValues(BinaryReader reader, out int length, out int position)
        {
            length = 0;
            position = 0;

            if (reader.RemainingLength() < 8)
                return false;

            length = reader.ReadUInt16();
            _ = reader.ReadUInt16();
            position = reader.ReadInt32();
            return true;
        }

        internal static bool TryParseAvPairs(BinaryReader reader, out List<NtlmAvPair> av_pairs)
        {
            av_pairs = new List<NtlmAvPair>();
            while (reader.RemainingLength() > 0)
            {
                if (!NtlmAvPair.TryParse(reader, out NtlmAvPair pair))
                {
                    return false;
                }
                if (pair.Type == MsAvPairType.EOL)
                    break;
                av_pairs.Add(pair);
            }
            return true;
        }

        public static bool ParseString(NtlmNegotiateFlags flags, byte[] data, int length, int position, out string result)
        {
            result = string.Empty;
            if (data.Length < position + length)
                return false;

            if (flags.HasFlagSet(NtlmNegotiateFlags.Unicode))
            {
                result = Encoding.Unicode.GetString(data, position, length);
            }
            else if (flags.HasFlagSet(NtlmNegotiateFlags.Oem))
            {
                result = BinaryEncoding.Instance.GetString(data, position, length);
            }
            else
            {
                return false;
            }

            return true;
        }

        public static bool ParseBytes(byte[] data, int length, int position, out byte[] result)
        {
            result = new byte[0];
            if (length == 0)
                return true;
            if (data.Length < position + length)
                return false;

            result = new byte[length];
            Array.Copy(data, position, result, 0, length);
            return true;
        }

        public static bool ParseString(NtlmNegotiateFlags flags, BinaryReader reader, byte[] data, bool valid, out string result)
        {
            result = string.Empty;
            if (!TryParseStringValues(reader, out int length, out int position))
                return false;

            if (!valid)
                return true;
            return ParseString(flags, data, length, position, out result);
        }

        internal static bool TryParse(BinaryReader reader, out Version version)
        {
            version = default;
            if (reader.RemainingLength() < 8)
                return false;

            int major = reader.ReadByte();
            int minor = reader.ReadByte();
            int build = reader.ReadUInt16();
            _ = reader.ReadBytes(3);
            int revision = reader.ReadByte();
            version = new Version(major, minor, build, revision);
            return true;
        }
    }
}
