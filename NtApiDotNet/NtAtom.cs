//  Copyright 2016 Google Inc. All Rights Reserved.
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
using System.Collections.Generic;
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

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus NtAddAtom(string String, int StringLength, out ushort Atom);

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus NtAddAtomEx(string String, int StringLength, out ushort Atom, int Flags);

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

    /// <summary>
    /// Class to handle NT atoms
    /// </summary>
    public class NtAtom
    {
        /// <summary>
        /// The atom value
        /// </summary>
        public ushort Atom { get; private set; }

        internal NtAtom(ushort atom)
        {
            Atom = atom;
        }

        /// <summary>
        /// Add an atom name
        /// </summary>
        /// <param name="name">The name to add</param>
        /// <returns>A reference to the atom</returns>
        public static NtAtom Add(string name)
        {
            ushort atom;
            NtSystemCalls.NtAddAtom(name + "\0", (name.Length + 1) * 2, out atom).ToNtException();
            return new NtAtom(atom);
        }

        /// <summary>
        /// Get the name of the stom
        /// </summary>
        /// <returns>The name of the atom</returns>
        public string Name
        {
            get
            {
                using (SafeStructureInOutBuffer<AtomBasicInformation> buffer = new SafeStructureInOutBuffer<AtomBasicInformation>(2048, false))
                {
                    int return_length;
                    NtSystemCalls.NtQueryInformationAtom(Atom, AtomInformationClass.AtomBasicInformation,
                         buffer, buffer.Length, out return_length).ToNtException();
                    AtomBasicInformation basic_info = buffer.Result;

                    return Marshal.PtrToStringUni(buffer.Data.DangerousGetHandle(), basic_info.NameLength / 2);
                }
            }
        }

        /// <summary>
        /// Enumerate all atoms.
        /// </summary>
        /// <returns>An enumeration of all atoms on the system.</returns>
        public static IEnumerable<NtAtom> GetAtoms()
        {
            int size = 1024;
            while (size < 5 * 1024 * 1024)
            {
                using (SafeStructureInOutBuffer<AtomTableInformation> buffer = new SafeStructureInOutBuffer<AtomTableInformation>(size, true))
                {
                    int return_length;
                    NtStatus status = NtSystemCalls.NtQueryInformationAtom(0, AtomInformationClass.AtomTableInformation, buffer, buffer.Length, out return_length);
                    if (status.IsSuccess())
                    {
                        AtomTableInformation table = buffer.Result;
                        IntPtr data = buffer.Data.DangerousGetHandle();
                        for (int i = 0; i < table.NumberOfAtoms; ++i)
                        {
                            ushort atom = (ushort)Marshal.ReadInt16(data);
                            yield return new NtAtom(atom);
                            data += 2;
                        }
                        
                    }
                    else if (status != NtStatus.STATUS_INFO_LENGTH_MISMATCH)
                    {
                        throw new NtException(status);
                    }
                    size *= 2;
                }
            }
        }
        
    }
}
