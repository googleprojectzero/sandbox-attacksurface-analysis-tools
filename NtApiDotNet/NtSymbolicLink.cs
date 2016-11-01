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

    /// <summary>
    /// Class representing a NT SymbolicLink object
    /// </summary>
    public class NtSymbolicLink : NtObjectWithDuplicate<NtSymbolicLink, SymbolicLinkAccessRights>
    {
        internal NtSymbolicLink(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        /// <summary>
        /// Create a symbolic link object.
        /// </summary>
        /// <param name="path">The path to the object</param>
        /// <param name="root">The root if path is relative</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <param name="target">The target path</param>
        /// <returns>The opened object</returns>
        public static NtSymbolicLink Create(string path, NtObject root, SymbolicLinkAccessRights desired_access, string target)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, desired_access, target);
            }
        }

        /// <summary>
        /// Create a symbolic link object.
        /// </summary>
        /// <param name="object_attributes">The object attributes for the object</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <param name="target">The target path</param>
        /// <returns>The opened object</returns>
        public static NtSymbolicLink Create(ObjectAttributes object_attributes, SymbolicLinkAccessRights desired_access, string target)
        {
            SafeKernelObjectHandle handle;
            NtSystemCalls.NtCreateSymbolicLinkObject(out handle,
                desired_access, object_attributes, new UnicodeString(target)).ToNtException();
            return new NtSymbolicLink(handle);
        }

        /// <summary>
        /// Create a symbolic link object.
        /// </summary>
        /// <param name="path">The path to the object</param>
        /// <param name="root">The root if path is relative</param>
        /// <param name="target">The target path</param>
        /// <returns>The opened object</returns>
        public static NtSymbolicLink Create(string path, NtObject root, string target)
        {
            return Create(path, root, SymbolicLinkAccessRights.MaximumAllowed, target);
        }

        /// <summary>
        /// Create a symbolic link object.
        /// </summary>
        /// <param name="path">The path to the object</param>
        /// <param name="target">The target path</param>
        /// <returns>The opened object</returns>
        public static NtSymbolicLink Create(string path, string target)
        {
            return Create(path, null, SymbolicLinkAccessRights.MaximumAllowed, target);
        }

        /// <summary>
        /// Open a symbolic link object.
        /// </summary>
        /// <param name="path">The path to the object</param>
        /// <param name="root">The root if path is relative</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <returns>The opened object</returns>
        public static NtSymbolicLink Open(string path, NtObject root, SymbolicLinkAccessRights desired_access)
        {
            using (ObjectAttributes obja = new ObjectAttributes(path, AttributeFlags.CaseInsensitive, root))
            {
                SafeKernelObjectHandle handle;
                NtSystemCalls.NtOpenSymbolicLinkObject(out handle,
                    desired_access, obja).ToNtException();
                return new NtSymbolicLink(handle);
            }
        }

        /// <summary>
        /// Open a symbolic link object.
        /// </summary>
        /// <param name="object_attributes">The object attributes for the object</param>
        /// <param name="desired_access">The desired access for the object</param>
        /// <returns>The opened object</returns>
        public static NtSymbolicLink Open(ObjectAttributes object_attributes, SymbolicLinkAccessRights desired_access)
        {
            SafeKernelObjectHandle handle;
            NtSystemCalls.NtOpenSymbolicLinkObject(out handle,
                desired_access, object_attributes).ToNtException();
            return new NtSymbolicLink(handle);
        }

        /// <summary>
        /// Open a symbolic link object.
        /// </summary>
        /// <param name="path">The path to the object</param>
        /// <param name="root">The root if path is relative</param>
        /// <returns>The opened object</returns>
        public static NtSymbolicLink Open(string path, NtObject root)
        {
            return Open(path, root, SymbolicLinkAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Open a symbolic link object.
        /// </summary>
        /// <param name="path">The path to the object</param>
        /// <returns>The opened object</returns>
        public static NtSymbolicLink Open(string path)
        {
            return Open(path, null);
        }

        /// <summary>
        /// Get the symbolic link target.
        /// </summary>
        public string Target
        {
            get
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
}
