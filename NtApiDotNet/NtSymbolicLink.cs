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
    public enum SymbolicLinkAccessRights : uint
    {
        Query = 1,        
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
        public static extern NtStatus NtCreateSymbolicLinkObject(
            out SafeKernelObjectHandle LinkHandle,
            SymbolicLinkAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes,
            UnicodeString DestinationName
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenSymbolicLinkObject(
            out SafeKernelObjectHandle LinkHandle,
            SymbolicLinkAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQuerySymbolicLinkObject(
            SafeHandle LinkHandle,
            [In, Out] UnicodeStringAllocated LinkTarget,
            out int ReturnedLength
        );
    }
#pragma warning restore 1591

    public class NtSymbolicLink : NtObjectWithDuplicate<NtSymbolicLink, SymbolicLinkAccessRights>
    {
        public NtSymbolicLink(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        public static NtSymbolicLink Create(string path, NtObject root, SymbolicLinkAccessRights access, string target)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, access, target);
            }
        }

        public static NtSymbolicLink Create(ObjectAttributes object_attributes, SymbolicLinkAccessRights access, string target)
        {
            SafeKernelObjectHandle handle;
            NtSystemCalls.NtCreateSymbolicLinkObject(out handle,
                access, object_attributes, new UnicodeString(target)).ToNtException();
            return new NtSymbolicLink(handle);
        }

        public static NtSymbolicLink Create(string path, NtObject root, string target)
        {
            return Create(path, root, SymbolicLinkAccessRights.MaximumAllowed, target);
        }

        public static NtSymbolicLink Create(string path, string target)
        {
            return Create(path, null, SymbolicLinkAccessRights.MaximumAllowed, target);
        }

        public static NtSymbolicLink Open(string path, NtObject root, SymbolicLinkAccessRights access)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle handle;
                NtSystemCalls.NtOpenSymbolicLinkObject(out handle,
                    access, obja).ToNtException();
                return new NtSymbolicLink(handle);
            }
        }

        public static NtSymbolicLink Open(ObjectAttributes object_attributes, SymbolicLinkAccessRights access)
        {
            SafeKernelObjectHandle handle;
            NtSystemCalls.NtOpenSymbolicLinkObject(out handle,
                access, object_attributes).ToNtException();
            return new NtSymbolicLink(handle);
        }

        public static NtSymbolicLink Open(string path, NtObject root)
        {
            return Open(path, root, SymbolicLinkAccessRights.MaximumAllowed);
        }

        

        public string Query()
        {
            using (UnicodeStringAllocated ustr = new UnicodeStringAllocated())
            {
                int return_length;
                NtSystemCalls.NtQuerySymbolicLinkObject(Handle, ustr, out return_length).ToNtException();
                return ustr.ToString();
            }
        }
    }
}
