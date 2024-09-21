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

// NOTE: This file is a modified version of SymbolResolver.cs from OleViewDotNet
// https://github.com/tyranid/oleviewdotnet. It's been relicensed from GPLv3 by
// the original author James Forshaw to be used under the Apache License for this
// project.

using NtCoreLib.Image;
using System;
using System.IO;

namespace NtCoreLib.Win32.Debugger.Symbols;

/// <summary>
/// Static class for creating symbol resolvers.
/// </summary>
public static class SymbolResolver
{
    #region Private Members
    private static string GetSymbolPath(string symbol_path)
    {
        if (!string.IsNullOrWhiteSpace(symbol_path))
            return symbol_path;
        if (!string.IsNullOrWhiteSpace(DefaultSymbolPath))
            return DefaultSymbolPath;
        string env_var = Environment.GetEnvironmentVariable("_NT_SYMBOL_PATH");
        if (!string.IsNullOrWhiteSpace(env_var))
            return env_var;
        return $"srv*{DbgHelpSymbolResolver.DEFAULT_SYMSRV}";
    }

    private static string GetDbgHelpPath(string dbghelp_path)
    {
        if (!string.IsNullOrWhiteSpace(dbghelp_path))
            return dbghelp_path;
        if (!string.IsNullOrWhiteSpace(DefaultDbgHelpPath))
            return DefaultDbgHelpPath;
        return "dbghelp.dll";
    }
    #endregion

    #region Static Properties
    /// <summary>
    /// Default path to debug help DLL. Used if no path explicitly specified.
    /// </summary>
    public static string DefaultDbgHelpPath { get; set; }

    /// <summary>
    /// Default symbol path. Used if no path is explicitly specified.
    /// </summary>
    public static string DefaultSymbolPath { get; set; }
    #endregion

    #region Static Methods
    /// <summary>
    /// Create a new instance of a symbol resolver.
    /// </summary>
    /// <param name="process">The process in which the symbols should be resolved.</param>
    /// <param name="dbghelp_path">The path to dbghelp.dll, ideally should use the one which comes with Debugging Tools for Windows.</param>
    /// <param name="symbol_path">The symbol path.</param>
    /// <param name="flags">Flags for the symbol resolver.</param>
    /// <param name="trace_writer">A text writer for output when specifying the <see cref="SymbolResolverFlags.TraceSymbolLoading">TraceSymbolLoading</see> flag.</param>
    /// <returns>The instance of a symbol resolver. Should be disposed when finished.</returns>
    public static ISymbolResolver Create(NtProcess process, string dbghelp_path = null, string symbol_path = null, SymbolResolverFlags flags = 0, TextWriter trace_writer = null)
    {
        return new DbgHelpSymbolResolver(process, GetDbgHelpPath(dbghelp_path), GetSymbolPath(symbol_path), flags, trace_writer);
    }

    /// <summary>
    /// Create a new instance of a symbol resolver based on an image file.
    /// </summary>
    /// <param name="image_file">The image file to use.</param>
    /// <param name="symbol_path">The symbol path.</param>
    /// <returns>The instance of a symbol resolver. Should be disposed when finished.</returns>
    public static ISymbolResolver Create(ImageFile image_file, string symbol_path)
    {
        if (image_file is null)
        {
            throw new ArgumentNullException(nameof(image_file));
        }

        return new DbgHelpSymbolResolver(image_file, GetSymbolPath(symbol_path));
    }
    #endregion
}
