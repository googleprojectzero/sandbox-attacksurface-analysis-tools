//  Copyright 2016, 2017, 2018 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Flags for the RPC server parser.
    /// </summary>
    [Flags]
    public enum RpcServerParserFlags
    {
        /// <summary>
        /// None.
        /// </summary>
        None = 0,
        /// <summary>
        /// Parse client entries.
        /// </summary>
        ParseClients = 1,
        /// <summary>
        /// Ignore symbols when parsing.
        /// </summary>
        IgnoreSymbols = 2,
        /// <summary>
        /// Try and resolve structure names. Needs private symbols.
        /// </summary>
        ResolveStructureNames = 4,
        /// <summary>
        /// Enable a symbol server fallback. If the copy of dbghelp doesn't have a symsrv.dll
        /// then download from a public symbol URL to a local cache directory during symbol
        /// resolving.
        /// </summary>
        SymSrvFallback = 8,
    }
}
