//  Copyright 2023 Google LLC. All Rights Reserved.
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
//
//  Note this is relicensed from OleViewDotNet by the author.

using System;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.SideBySide.Interop;

// The hash table bucket chain is then a list of offsets from the section header to
// the section entries for the chain.
[StructLayout(LayoutKind.Sequential)]
struct ACTIVATION_CONTEXT_GUID_SECTION_ENTRY
{
    public Guid Guid;
    public int Offset;               // offset from the section header
    public int Length;               // in bytes
    public int AssemblyRosterIndex;  // 1-based index into the assembly roster for the assembly that
                                     // provided this entry.  If the entry is not associated with
                                     // an assembly, zero.
}
