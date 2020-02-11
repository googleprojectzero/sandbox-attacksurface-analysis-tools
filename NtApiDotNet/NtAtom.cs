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
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Class to handle NT atoms
    /// </summary>
    public sealed class NtAtom
    {
        #region Constructors

        internal NtAtom(ushort atom)
        {
            Atom = atom;
        }

        #endregion

        #region Static Methods

        /// <summary>
        /// Add an atom name
        /// </summary>
        /// <param name="name">The name to add</param>
        /// <param name="flags">Flags for the add.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>A reference to the atom</returns>
        public static NtResult<NtAtom> Add(string name, AddAtomFlags flags, bool throw_on_error)
        {
            if (flags == AddAtomFlags.None)
            {
                return NtSystemCalls.NtAddAtom(name + "\0", (name.Length + 1) * 2,
                    out ushort atom).CreateResult(throw_on_error, () => new NtAtom(atom));
            }
            else
            {
                return NtSystemCalls.NtAddAtomEx(name + "\0", (name.Length + 1) * 2,
                    out ushort atom, flags).CreateResult(throw_on_error, () => new NtAtom(atom));
            }
        }

        /// <summary>
        /// Add an atom name
        /// </summary>
        /// <param name="name">The name to add</param>
        /// <param name="flags">Flags for the add.</param>
        /// <returns>A reference to the atom</returns>
        public static NtAtom Add(string name, AddAtomFlags flags)
        {
            return Add(name, flags, true).Result;
        }

        /// <summary>
        /// Add an atom name
        /// </summary>
        /// <param name="name">The name to add</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>A reference to the atom</returns>
        public static NtResult<NtAtom> Add(string name, bool throw_on_error)
        {
            return Add(name, AddAtomFlags.None, throw_on_error);
        }

        /// <summary>
        /// Add an atom name
        /// </summary>
        /// <param name="name">The name to add</param>
        /// <returns>A reference to the atom</returns>
        public static NtAtom Add(string name)
        {
            return Add(name, AddAtomFlags.None);
        }

        /// <summary>
        /// Find an atom by name.
        /// </summary>
        /// <param name="name">The name of the atom.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The found atom.</returns>
        public static NtResult<NtAtom> Find(string name, bool throw_on_error)
        {
            return NtSystemCalls.NtFindAtom(name + "\0", (name.Length + 1) * 2, 
                out ushort atom).CreateResult(throw_on_error, () => new NtAtom(atom));
        }

        /// <summary>
        /// Find an atom by name.
        /// </summary>
        /// <param name="name">The name of the atom.</param>
        /// <returns>The found atom.</returns>
        public static NtAtom Find(string name)
        {
            return Find(name, true).Result;
        }

        /// <summary>
        /// Query if the atom exists.
        /// </summary>
        /// <param name="atom">The atom to check.</param>
        /// <returns>True if the atom exists.</returns>
        public static bool Exists(ushort atom)
        {
            return new NtAtom(atom).GetName(false).IsSuccess;
        }

        /// <summary>
        /// Open an atom by number.
        /// </summary>
        /// <param name="atom">The atom to open.</param>
        /// <param name="check_exists">True to check atom exists.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The atom object.</returns>
        public static NtResult<NtAtom> Open(ushort atom, bool check_exists, bool throw_on_error)
        {
            NtAtom ret = new NtAtom(atom);
            if (check_exists)
            {
                return ret.GetName(false).Status.CreateResult(throw_on_error, () => ret);
            }
            return ret.CreateResult();
        }

        /// <summary>
        /// Open an atom by number.
        /// </summary>
        /// <param name="atom">The atom to open.</param>
        /// <param name="check_exists">True to check atom exists.</param>
        /// <returns>The atom object.</returns>
        public static NtAtom Open(ushort atom, bool check_exists)
        {
            return Open(atom, check_exists, true).Result;
        }

        /// <summary>
        /// Open an atom by number.
        /// </summary>
        /// <param name="atom">The atom to open.</param>
        /// <returns>The atom object.</returns>
        public static NtAtom Open(ushort atom)
        {
            return Open(atom, true);
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
                using (var buffer = new SafeStructureInOutBuffer<AtomTableInformation>(size, true))
                {
                    NtStatus status = NtSystemCalls.NtQueryInformationAtom(0,
                        AtomInformationClass.AtomTableInformation, buffer, buffer.Length, out int return_length);
                    if (status.IsSuccess())
                    {
                        AtomTableInformation table = buffer.Result;
                        IntPtr data = buffer.Data.DangerousGetHandle();
                        ushort[] atoms = new ushort[table.NumberOfAtoms];
                        buffer.Data.ReadArray(0, atoms, 0, atoms.Length);
                        return atoms.Select(a => new NtAtom(a));
                    }
                    else if (status != NtStatus.STATUS_INFO_LENGTH_MISMATCH)
                    {
                        throw new NtException(status);
                    }
                    size *= 2;
                }
            }
            return new NtAtom[0];
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Delete an atom.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus Delete(bool throw_on_error)
        {
            return NtSystemCalls.NtDeleteAtom(Atom).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Delete an atom.
        /// </summary>
        public void Delete()
        {
            Delete(true);
        }

        /// <summary>
        /// Get the name of the atom.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The name of the atom.</returns>
        public NtResult<string> GetName(bool throw_on_error)
        {
            using (var buffer = new SafeStructureInOutBuffer<AtomBasicInformation>(2048, false))
            {
                return NtSystemCalls.NtQueryInformationAtom(Atom, AtomInformationClass.AtomBasicInformation,
                     buffer, buffer.Length, out int return_length)
                     .CreateResult(throw_on_error, () => buffer.Data.ReadUnicodeString(buffer.Result.NameLength / 2));
            }
        }

        #endregion

        #region Public Properties

        /// <summary>
        /// The atom value
        /// </summary>
        public ushort Atom { get; }

        /// <summary>
        /// Get the name of the atom.
        /// </summary>
        /// <returns>The name of the atom</returns>
        public string Name => GetName(true).Result;

        #endregion
    }
}
