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
struct ACTIVATION_CONTEXT_GUID_SECTION_HEADER
{
    public uint Magic;
    public int HeaderSize;               // in bytes
    public int FormatVersion;
    public int DataFormatVersion;
    public ACTIVATION_CONTEXT_GUID_SECTION_FLAGS Flags;
    public int ElementCount;
    public int ElementListOffset;        // offset from section header
    public int SearchStructureOffset;    // offset from section header
    public int UserDataOffset;           // offset from section header
    public int UserDataSize;             // in bytes
}
