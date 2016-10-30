//  Copyright 2016 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
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
    [Flags]
    public enum MutantAccessRights : uint
    {
        None = 0,
        QueryState = 1,
        GenericRead = GenericAccessRights.GenericRead,
        GenericWrite = GenericAccessRights.GenericWrite,
        GenericExecute = GenericAccessRights.GenericExecute,
        GenericAll = GenericAccessRights.GenericAll,
        Delete = GenericAccessRights.Delete,
        ReadControl = GenericAccessRights.ReadControl,
        WriteDac = GenericAccessRights.WriteDac,
        WriteOwner = GenericAccessRights.WriteOwner,
        Synchronize = GenericAccessRights.Synchronize,
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateMutant(out SafeKernelObjectHandle MutantHandle, MutantAccessRights DesiredAccess, 
            ObjectAttributes ObjectAttributes, bool InitialOwner);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenMutant(out SafeKernelObjectHandle MutantHandle, MutantAccessRights DesiredAccess, 
            ObjectAttributes ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtReleaseMutant(SafeKernelObjectHandle MutantHandle, out uint PreviousState);
    }
#pragma warning restore 1591

    public class NtMutant : NtObjectWithDuplicate<NtMutant, MutantAccessRights>
    {
        internal NtMutant(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        public static NtMutant Create(string name, NtObject root, bool initial_owner)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, initial_owner, MutantAccessRights.MaximumAllowed);
            }
        }

        public static NtMutant Create(ObjectAttributes object_attributes, bool initial_owner, MutantAccessRights access_rights)
        {
            SafeKernelObjectHandle handle;
            NtSystemCalls.NtCreateMutant(out handle, access_rights, object_attributes, initial_owner).ToNtException();
            return new NtMutant(handle);
        }

        public static NtMutant Open(string name, NtObject root, MutantAccessRights access_rights)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obja, access_rights);
            }
        }

        public static NtMutant Open(ObjectAttributes object_attributes, MutantAccessRights access_rights)
        {
            SafeKernelObjectHandle handle;
            NtSystemCalls.NtOpenMutant(out handle, access_rights, object_attributes).ToNtException();
            return new NtMutant(handle);
        }

        public uint Release()
        {
            uint ret = 0;
            NtSystemCalls.NtReleaseMutant(Handle, out ret).ToNtException();
            return ret;
        }
    }
}
