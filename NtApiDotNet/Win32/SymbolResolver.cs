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

using NtApiDotNet.Win32.Debugger;
using System;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Static class for create symbolc resolvers.
    /// </summary>
    public static class SymbolResolver
    {
        /// <summary>
        /// Create a new instance of a symbol resolver.
        /// </summary>
        /// <param name="process">The process in which the symbols should be resolved.</param>
        /// <param name="dbghelp_path">The path to dbghelp.dll, ideally should use the one which comes with Debugging Tools for Windows.</param>
        /// <param name="symbol_path">The symbol path.</param>
        /// <returns>The instance of a symbol resolver. Should be disposed when finished.</returns>
        public static ISymbolResolver Create(NtProcess process, string dbghelp_path, string symbol_path)
        {
            return new DbgHelpSymbolResolver(process, dbghelp_path, symbol_path);
        }

        /// <summary>
        /// Create a new instance of a symbol resolver. Uses the system dbghelp library and symbol path
        /// from _NT_SYMBOL_PATH environment variable.
        /// </summary>
        /// <param name="process">The process in which the symbols should be resolved.</param>
        /// <returns>The instance of a symbol resolver. Should be disposed when finished.</returns>
        public static ISymbolResolver Create(NtProcess process)
        {
            string symbol_path = Environment.GetEnvironmentVariable("_NT_SYMBOL_PATH");
            if (string.IsNullOrWhiteSpace(symbol_path))
            {
                throw new ArgumentException("_NT_SYMBOL_PATH environment variable not specified");
            }

            return Create(process, "dbghelp.dll", symbol_path);
        }
    }
}
