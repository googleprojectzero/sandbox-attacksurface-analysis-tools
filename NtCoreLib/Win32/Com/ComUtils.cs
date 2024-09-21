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

// NOTE: This file is a modified version of COMProxyInstance.cs from OleViewDotNet
// https://github.com/tyranid/oleviewdotnet. It's been relicensed from GPLv3 by
// the original author James Forshaw to be used under the Apache License for this
// project.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;

#nullable enable

namespace NtCoreLib.Win32.Com;

/// <summary>
/// Utilities functions for COM.
/// </summary>
public static class ComUtils
{
    #region Private Members
    private static readonly ConcurrentDictionary<string, string> _demangled_names = new();

    private static string GetNextToken(string name, out string token)
    {
        token = string.Empty;
        if (name.Length == 0)
        {
            return name;
        }
        int end_index = name.IndexOf('_');
        if (end_index < 0)
        {
            token = name;
        }
        else
        {
            token = name.Substring(0, end_index);
        }
        return name.Substring(end_index + 1).TrimStart('_');
    }

    private static string GetNextToken(string name, out int token)
    {
        if (name.Length == 0 || !char.IsDigit(name[0]))
        {
            throw new ArgumentException("Expected an integer.", nameof(name));
        }
        int length = 0;
        while (char.IsDigit(name[length]))
        {
            length++;
        }

        token = int.Parse(name.Substring(0, length));

        return name.Substring(length).TrimStart('_');
    }

    private static string ReadType(ref string name)
    {
        name = GetNextToken(name, out string token);
        if (string.IsNullOrEmpty(token))
        {
            throw new ArgumentException("Expected a type name.", nameof(token));
        }

        if (char.IsLetter(token[0]))
        {
            return token;
        }
        else if (token[0] == '~')
        {
            StringBuilder builder = new();
            name = GetNextToken(name, out int type_count);
            builder.Append(token.Substring(1));
            builder.Append("<");
            List<string> types = new();
            for (int i = 0; i < type_count; ++i)
            {
                types.Add(ReadType(ref name));
            }
            builder.Append(string.Join(",", types));
            builder.Append(">");
            return builder.ToString();
        }
        else
        {
            throw new ArgumentException("Expected a type name or a generic type");
        }
    }

    private static string DemangleGenericType(string name)
    {
        name = name.Replace("__F", "~").Replace("__C", "::");
        return ReadType(ref name);
    }

    private static string DemangleName(string name)
    {
        if (name == string.Empty)
        {
            throw new ArgumentException("Interface name can't be empty.", nameof(name));
        }
        if (name.StartsWith("__x_") || name.StartsWith("___x_"))
        {
            return name.Substring(4).Replace("_C", "::");
        }
        else if (name.StartsWith("__F"))
        {
            try
            {
                return DemangleGenericType(name);
            }
            catch (ArgumentException)
            {
            }
        }
        return name;
    }
    #endregion

    /// <summary>
    /// Try and demangle a WinRT interface name.
    /// </summary>
    /// <param name="name">The name to demangle.</param>
    /// <returns>The demangled name.</returns>
    public static string DemangleWinRTName(string name) => _demangled_names.GetOrAdd(name?.Trim() ?? string.Empty, DemangleName);
}