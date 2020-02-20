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
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet
{
    /// <summary>
    /// Utilities for registry keys.
    /// </summary>
    public static class NtKeyUtils
    {
        private static Dictionary<string, string> CreateWin32BaseKeys()
        {
            Dictionary<string, string> dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "HKLM", @"\Registry\Machine" },
                { "HKEY_LOCAL_MACHINE", @"\Registry\Machine" },
                { "HKU", @"\Registry\User" },
                { "HKEY_USERS", @"\Registry\User" },
                { "HKEY_CURRENT_CONFIG", @"\Registry\Machine\System\CurrentControlSet\Hardware Profiles\Current" },
                { "HKCC", @"\Registry\Machine\System\CurrentControlSet\Hardware Profiles\Current" },
            };
            using (var token = NtToken.OpenProcessToken(NtProcess.Current, TokenAccessRights.Query, false))
            {
                if (token.IsSuccess)
                {
                    string current_user = $@"\Registry\User\{token.Result.User.Sid}";
                    dict.Add("HKCU", current_user);
                    dict.Add("HKEY_CURRENT_USER", current_user);
                }
            }
            dict.Add("HKEY_CLASSES_ROOT", @"\Registry\Machine\Software\Classes");
            dict.Add("HKCR", @"\Registry\Machine\Software\Classes");
            return dict;
        }

        private static Dictionary<string, string> _win32_base_keys = CreateWin32BaseKeys();

        /// <summary>
        /// Convert a Win32 style keyname such as HKEY_LOCAL_MACHINE\Path into a native key path.
        /// </summary>
        /// <param name="path">The win32 style keyname to convert.</param>
        /// <returns>The converted keyname.</returns>
        /// <exception cref="NtException">Thrown if invalid name.</exception>
        public static string Win32KeyNameToNt(string path)
        {
            foreach (var pair in _win32_base_keys)
            {
                if (path.Equals(pair.Key, StringComparison.OrdinalIgnoreCase))
                {
                    return pair.Value;
                }
                else if (path.StartsWith(pair.Key + @"\", StringComparison.OrdinalIgnoreCase))
                {
                    return pair.Value + path.Substring(pair.Key.Length);
                }
            }
            throw new NtException(NtStatus.STATUS_OBJECT_NAME_INVALID);
        }

        class StringLengthComparer : IComparer<string>
        {
            public int Compare(string x, string y)
            {
                return y.Length - x.Length;
            }
        }

        /// <summary>
        /// Attempt to convert an NT style registry key name to Win32 form.
        /// If it's not possible to convert the function will return the 
        /// original form.
        /// </summary>
        /// <param name="nt_path">The NT path to convert.</param>
        /// <returns>The converted path, or original if it can't be converted.</returns>
        public static string NtKeyNameToWin32(string nt_path)
        {
            foreach (var pair in _win32_base_keys.OrderBy(p => p.Value, new StringLengthComparer()))
            {
                if (nt_path.Equals(pair.Value, StringComparison.OrdinalIgnoreCase))
                {
                    return pair.Key;
                }
                else if (nt_path.StartsWith(pair.Value + @"\", StringComparison.OrdinalIgnoreCase))
                {
                    return pair.Key + nt_path.Substring(pair.Value.Length);
                }
            }
            return nt_path;
        }
    }
}
