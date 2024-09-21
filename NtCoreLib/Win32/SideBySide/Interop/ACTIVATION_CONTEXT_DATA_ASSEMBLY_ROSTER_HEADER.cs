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
struct ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER
{
    public int HeaderSize;
    public uint HashAlgorithm;
    public int EntryCount;               // Entry 0 is reserved; this is the number of assemblies plus 1.
    public int FirstEntryOffset;         // From ACTIVATION_CONTEXT_DATA base
    public int AssemblyInformationSectionOffset; // Offset from the ACTIVATION_CONTEXT_DATA base to the
                                                 // header of the assembly information string section.  Needed because
                                                 // the roster entries contain the offsets from the ACTIVATION_CONTEXT_DATA
                                                 // to the assembly information structs, but those structs contain offsets
                                                 // from their section base to the strings etc.
}
