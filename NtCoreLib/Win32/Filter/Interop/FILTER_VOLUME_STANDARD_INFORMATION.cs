//  Copyright 2020 Google Inc. All Rights Reserved.
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

using NtCoreLib.Utilities.Data;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Filter.Interop;

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode), DataStart("FilterVolumeName")]
internal struct FILTER_VOLUME_STANDARD_INFORMATION
{
    public int NextEntryOffset;
    public FILTER_VOLUME_STANDARD_INFORMATION_FLAGS Flags;
    public int FrameID;
    public FilterFilesystemType FileSystemType;
    public ushort FilterVolumeNameLength;
    public char FilterVolumeName;
}
