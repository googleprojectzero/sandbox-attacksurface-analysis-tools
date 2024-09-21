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

using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Debugger
{
    [Flags]
    enum SYMBOL_INFO_FLAGS
    {
        SYMFLAG_VALUEPRESENT = 0x00000001,
        SYMFLAG_REGISTER = 0x00000008,
        SYMFLAG_REGREL = 0x00000010,
        SYMFLAG_FRAMEREL = 0x00000020,
        SYMFLAG_PARAMETER = 0x00000040,
        SYMFLAG_LOCAL = 0x00000080,
        SYMFLAG_CONSTANT = 0x00000100,
        SYMFLAG_EXPORT = 0x00000200,
        SYMFLAG_FORWARDER = 0x00000400,
        SYMFLAG_FUNCTION = 0x00000800,
        SYMFLAG_VIRTUAL = 0x00001000,
        SYMFLAG_THUNK = 0x00002000,
        SYMFLAG_TLSREL = 0x00004000,
        SYMFLAG_SLOT = 0x00008000,
        SYMFLAG_ILREL = 0x00010000,
        SYMFLAG_METADATA = 0x00020000,
        SYMFLAG_CLR_TOKEN = 0x00040000,
        SYMFLAG_NULL = 0x00080000,
        SYMFLAG_FUNC_NO_RETURN = 0x00100000,
        SYMFLAG_SYNTHETIC_ZEROBASE = 0x00200000,
        SYMFLAG_PUBLIC_CODE = 0x00400000,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode), DataStart("Name")]
    class SYMBOL_INFO
    {
        public int SizeOfStruct;
        public int TypeIndex;        // Type Index of symbol
        public long Reserved1;
        public long Reserved2;
        public int Index;
        public int Size;
        public long ModBase;          // Base Address of module comtaining this symbol
        public SYMBOL_INFO_FLAGS Flags;
        public long Value;            // Value of symbol, ValuePresent should be 1
        public long Address;          // Address of symbol including base address of module
        public int Register;         // register holding value or pointer to value
        public int Scope;            // scope of the symbol
        public SymTagEnum Tag;              // pdb classification
        public int NameLen;          // Actual length of name
        public int MaxNameLen;
        public char Name;

        public const int MAX_SYM_NAME = 2000;

        public SYMBOL_INFO()
        {
            SizeOfStruct = Marshal.SizeOf(typeof(SYMBOL_INFO));
        }

        public SYMBOL_INFO(int max_name_len) : this()
        {
            MaxNameLen = max_name_len;
        }
    }
}
