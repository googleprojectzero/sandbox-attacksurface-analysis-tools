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

// NOTE: This file is a modified version of NdrParser.cs from OleViewDotNet
// https://github.com/tyranid/oleviewdotnet. It's been relicensed from GPLv3 by
// the original author James Forshaw to be used under the Apache License for this
// project.

using NtCoreLib.Ndr.Dce;
using NtCoreLib.Ndr.Interop;
using NtCoreLib.Utilities.Memory;
using NtCoreLib.Win32.Debugger.Symbols;
using System;
using System.Collections.Generic;

namespace NtCoreLib.Ndr.Parser;

internal class NdrParseContext
{
    public NdrTypeCache TypeCache { get; }
    public ISymbolResolver SymbolResolver { get; }
    public MIDL_STUB_DESC StubDesc { get; }
    public IntPtr TypeDesc { get; }
    public IMemoryReader Reader { get; }
    public NdrParserFlags Flags { get; }
    public NDR_EXPR_DESC ExprDesc { get; }
    public NdrInterpreterOptFlags2 OptFlags { get; }
    public Dictionary<int, NdrUnionArms> UnionArmsCache { get; }

    public bool HasFlag(NdrParserFlags flags)
    {
        return (Flags & flags) == flags;
    }

    internal NdrParseContext(NdrTypeCache type_cache, ISymbolResolver symbol_resolver,
        MIDL_STUB_DESC stub_desc, IntPtr type_desc, NDR_EXPR_DESC expr_desc,
        NdrInterpreterOptFlags2 opt_flags, IMemoryReader reader, NdrParserFlags parser_flags,
        Dictionary<int, NdrUnionArms> union_arms_cache)
    {
        TypeCache = type_cache;
        SymbolResolver = symbol_resolver;
        StubDesc = stub_desc;
        TypeDesc = type_desc;
        ExprDesc = expr_desc;
        OptFlags = opt_flags;
        Reader = reader;
        Flags = parser_flags;
        UnionArmsCache = union_arms_cache;
    }
}
