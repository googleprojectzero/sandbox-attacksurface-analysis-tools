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

using System.Runtime.InteropServices;

namespace NtApiDotNet.ApiSet
{
    // Based on http://www.geoffchappell.com/studies/windows/win32/apisetschema/index.htm.
    [StructLayout(LayoutKind.Sequential)]
    internal struct API_SET_NAMESPACE_WIN10
    {
        public int Version;
        public int Size;
        public ApiSetFlags Flags;
        public int Count;
        public int NamespaceOffset;
        public int HashEntryOffset;
        public int HashMultiplier;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct API_SET_NAMESPACE_ENTRY_WIN10
    {
        public ApiSetFlags Flags;
        public int NameOffset;
        public int NameLength;
        public int HashLength;
        public int ValueOffset;
        public int ValueCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct API_SET_VALUE_ENTRY_WIN10
    {
        public int Flags;
        public int NameOffset;
        public int NameLength;
        public int ValueOffset;
        public int ValueLength;
    }
}
