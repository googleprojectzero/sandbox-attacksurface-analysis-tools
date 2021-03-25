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

using System;

namespace NtApiDotNet.Utilities.Text
{
    /// <summary>
    /// Class to call NT functions for manipulating strings.
    /// </summary>
    public static class StringUtils
    {
        #region Static Members
        /// <summary>
        /// Upper case a character according to the internal NTDLL string routines.
        /// </summary>
        /// <param name="c">The character to upper case.</param>
        /// <returns>The upper case character.</returns>
        public static char Upcase(char c)
        {
            return NtRtl.RtlUpcaseUnicodeChar(c);
        }

        /// <summary>
        /// Upper case a string according to the internal NTDLL string routines.
        /// </summary>
        /// <param name="str">The string to upper case.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The upper case string.</returns>
        public static NtResult<string> Upcase(string str, bool throw_on_error)
        {
            UnicodeStringOut out_str = new UnicodeStringOut();
            try
            {
                return NtRtl.RtlUpcaseUnicodeString(ref out_str, new UnicodeString(str), true).CreateResult(throw_on_error, () => out_str.ToString());
            }
            finally
            {
                NtRtl.RtlFreeUnicodeString(ref out_str);
            }
        }

        /// <summary>
        /// Upper case a string according to the internal NTDLL string routines.
        /// </summary>
        /// <param name="str">The string to upper case.</param>
        /// <returns>The upper case string.</returns>
        public static string Upcase(string str)
        {
            return Upcase(str, true).Result;
        }

        /// <summary>
        /// Lower case a character according to the internal NTDLL string routines.
        /// </summary>
        /// <param name="c">The character to lower case.</param>
        /// <returns>The lower case character.</returns>
        public static char Downcase(char c)
        {
            return NtRtl.RtlUpcaseUnicodeChar(c);
        }

        /// <summary>
        /// Lower case a string according to the internal NTDLL string routines.
        /// </summary>
        /// <param name="str">The string to lower case.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The lower case string.</returns>
        public static NtResult<string> Downcase(string str, bool throw_on_error)
        {
            UnicodeStringOut out_str = new UnicodeStringOut();
            try
            {
                return NtRtl.RtlUpcaseUnicodeString(ref out_str, new UnicodeString(str), true).CreateResult(throw_on_error, () => out_str.ToString());
            }
            finally
            {
                NtRtl.RtlFreeUnicodeString(ref out_str);
            }
        }

        /// <summary>
        /// Lower case a string according to the internal NTDLL string routines.
        /// </summary>
        /// <param name="str">The string to lower case.</param>
        /// <returns>The lower case string.</returns>
        public static string Downcase(string str)
        {
            return Upcase(str, true).Result;
        }

        /// <summary>
        /// Parse a hex string into a byte array.
        /// </summary>
        /// <param name="str">The hex string. Can contain spaces.</param>
        /// <returns>The parsed string as a byte array.</returns>
        public static byte[] ParseHex(string str)
        {
            if (str.Length == 0)
                return new byte[0];
            str = str.Replace(" ", "");
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
        /// <param name="str">The hex string. Can contain spaces.</param>
        /// <param name="data">The parsed string as a byte array.</param>
        /// <returns>True if the parse was successful.</returns>
        public static bool TryParseHex(string str, out byte[] data)
        {
            data = null;
            try
            {
                data = ParseHex(str);
                return true;
            }
            catch (FormatException)
            {
                return false;
            }
        }
        #endregion

        #region Private Members
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
    }
}
