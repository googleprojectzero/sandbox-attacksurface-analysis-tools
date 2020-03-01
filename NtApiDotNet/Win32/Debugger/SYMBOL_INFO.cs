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

using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Debugger
{
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
        public int Flags;
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
