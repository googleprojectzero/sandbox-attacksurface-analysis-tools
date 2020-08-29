//  Copyright 2018 Google Inc. All Rights Reserved.
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

using NtApiDotNet;
using NtApiDotNet.Utilities.Text;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Management.Automation;
using System.Text;
using System.Text.RegularExpressions;

namespace NtObjectManager.Utils
{
    /// <para type="description">Enumeration to specify a text encoding.</para>
    public enum TextEncodingType
    {
        /// <summary>
        /// Binary raw text.
        /// </summary>
        Binary,
        /// <summary>
        /// 16 bit unicode text.
        /// </summary>
        Unicode,
        /// <summary>
        /// Big Endian 16 bit unicode text.
        /// </summary>
        BigEndianUnicode,
        /// <summary>
        /// UTF8
        /// </summary>
        UTF8,
        /// <summary>
        /// UTF32
        /// </summary>
        UTF32,
        /// <summary>
        /// UTF7
        /// </summary>
        UTF7
    }

    /// <summary>
    /// Some utility functions for PowerShell.
    /// </summary>
    public static class PSUtils
    {
        internal static T InvokeWithArg<T>(this ScriptBlock script_block, T default_value, params object[] args) 
        {
            try
            {
                List<PSVariable> vars = new List<PSVariable>();
                if (args.Length > 0)
                {
                    vars.Add(new PSVariable("_", args[0]));
                }
                var os = script_block.InvokeWithContext(null, vars, args);
                if (os.Count > 0)
                {
                    return (T)Convert.ChangeType(os[0].BaseObject, typeof(T));
                }
            }
            catch
            {
            }
            return default_value;
        }

        internal static Collection<PSObject> InvokeWithArg(this ScriptBlock script_block, params object[] args)
        {
            List<PSVariable> vars = new List<PSVariable>();
            if (args.Length > 0)
            {
                vars.Add(new PSVariable("_", args[0]));
            }
            return script_block.InvokeWithContext(null, vars, args);
        }

        internal static Encoding GetEncoding(TextEncodingType encoding)
        {
            switch (encoding)
            {
                case TextEncodingType.Binary:
                    return BinaryEncoding.Instance;
                case TextEncodingType.Unicode:
                    return Encoding.Unicode;
                case TextEncodingType.BigEndianUnicode:
                    return Encoding.BigEndianUnicode;
                case TextEncodingType.UTF8:
                    return Encoding.UTF8;
                case TextEncodingType.UTF32:
                    return Encoding.UTF32;
                case TextEncodingType.UTF7:
                    return Encoding.UTF7;
                default:
                    throw new ArgumentException("Unknown text encoding", nameof(encoding));
            }
        }

        internal static void AddDynamicParameter(this RuntimeDefinedParameterDictionary dict, string name, Type type, bool mandatory, int? position = null)
        {
            Collection<Attribute> attrs = new Collection<Attribute>();
            ParameterAttribute attr = new ParameterAttribute
            {
                Mandatory = mandatory
            };
            if (position.HasValue)
            {
                attr.Position = position.Value;
            }
            attrs.Add(attr);
            dict.Add(name, new RuntimeDefinedParameter(name, type, attrs));
        }

        internal static bool GetValue<T>(this RuntimeDefinedParameterDictionary dict, string name, out T value) where T : class
        {
            value = default;
            if (!dict.ContainsKey(name))
                return false;
            if (dict[name].Value is T result)
            {
                value = result;
                return true;
            }
            return false;
        }

        internal static bool GetValue<T>(this RuntimeDefinedParameterDictionary dict, string name, out T? value) where T : struct
        {
            value = default;
            if (!dict.ContainsKey(name))
                return false;
            if (dict[name].Value is T result)
            {
                value = result;
                return true;
            }
            return false;
        }

        internal static Regex GlobToRegex(string glob, bool case_sensitive)
        {
            string escaped = Regex.Escape(glob);
            return new Regex("^" + escaped.Replace("\\*", ".*").Replace("\\?", ".") + "$", !case_sensitive ? RegexOptions.IgnoreCase : RegexOptions.None);
        }

        internal static bool HasGlobChars(string s)
        {
            return s.Contains("*") || s.Contains("?");
        }

        private static string ResolveRelativePath(SessionState state, string path, RtlPathType path_type)
        {
            var current_path = state.Path.CurrentFileSystemLocation;
            if (!current_path.Provider.Name.Equals("FileSystem", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("Can't make a relative Win32 path when not in a file system drive.");
            }

            switch (path_type)
            {
                case RtlPathType.Relative:
                    return Path.Combine(current_path.Path, path);
                case RtlPathType.Rooted:
                    return $"{current_path.Drive.Name}:{path}";
                case RtlPathType.DriveRelative:
                    if (path.Substring(0, 1).Equals(current_path.Drive.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        return Path.Combine(current_path.Path, path.Substring(2));
                    }
                    break;
            }

            return path;
        }

        /// <summary>
        /// Resolve a Win32 path using current PS session state.
        /// </summary>
        /// <param name="state">The session state.</param>
        /// <param name="path">The path to resolve.</param>
        /// <returns>The resolved Win32 path.</returns>
        public static string ResolveWin32Path(SessionState state, string path)
        {
            var path_type = NtFileUtils.GetDosPathType(path);
            if (path_type == RtlPathType.Rooted && path.StartsWith(@"\??"))
            {
                path_type = RtlPathType.LocalDevice;
            }
            switch (path_type)
            {
                case RtlPathType.Relative:
                case RtlPathType.DriveRelative:
                case RtlPathType.Rooted:
                    path = ResolveRelativePath(state, path, path_type);
                    break;
            }

            return NtFileUtils.DosFileNameToNt(path);
        }

        internal static string ResolvePath(SessionState state, string path, bool win32_path)
        {
            if (win32_path)
            {
                return ResolveWin32Path(state, path);
            }
            else
            {
                return path;
            }
        }

        private static void DisposeObject(object obj)
        {
            IDisposable disp = obj as IDisposable;
            if (obj is PSObject psobj)
            {
                disp = psobj.BaseObject as IDisposable;
            }

            if (disp != null)
            {
                disp.Dispose();
            }
        }

        internal static void Dispose(object input)
        {
            if (input is IEnumerable e)
            {
                foreach (object obj in e)
                {
                    DisposeObject(obj);
                }
            }
            else
            {
                DisposeObject(input);
            }
        }
    }
}
