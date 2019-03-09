//  Copyright 2019 Google Inc. All Rights Reserved.
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
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    public enum AtomInformationClass
    {
        AtomBasicInformation,
        AtomTableInformation
    }

    [StructLayout(LayoutKind.Sequential)]
    public class AtomBasicInformation
    {
        public ushort UsageCount;
        public ushort Flags;
        public ushort NameLength;
        //WCHAR Name[1];
    }

    [StructLayout(LayoutKind.Sequential)]
    public class AtomTableInformation
    {
        public int NumberOfAtoms;
        //RTL_ATOM Atoms[1];
    }

    [Flags]
    public enum AddAtomFlags
    {
        None = 0,
        Global = 2,
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus NtAddAtom(string String, int StringLength, out ushort Atom);

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus NtAddAtomEx(string String, int StringLength, out ushort Atom, AddAtomFlags Flags);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtDeleteAtom(ushort Atom);

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus NtFindAtom(string String, int StringLength, out ushort Atom);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryInformationAtom(
            ushort Atom,
            AtomInformationClass AtomInformationClass,
            SafeBuffer AtomInformation,
            int AtomInformationLength,
            out int ReturnLength
        );
    }
#pragma warning restore 1591
}
