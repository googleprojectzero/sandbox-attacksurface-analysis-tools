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

using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.SideBySide.Interop;

[StructLayout(LayoutKind.Sequential)]
struct ACTIVATION_CONTEXT_STRING_SECTION_ENTRY
{
    public int PseudoKey;
    public int KeyOffset;            // offset from the section header
    public int KeyLength;            // in bytes
    public int Offset;               // offset from the section header
    public int Length;               // in bytes
    public int AssemblyRosterIndex;  // 1-based index into the assembly roster for the assembly that
                                     // provided this entry.  If the entry is not associated with
                                     // an assembly, zero.
}
