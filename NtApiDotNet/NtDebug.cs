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
    public enum DebugAccessRights : uint
    {
        ReadEvent = 0x1,
        ProcessAssign = 0x2,
        SetInformation = 0x4,
        QueryInformation = 0x8,
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
        AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtDebugActiveProcess(SafeKernelObjectHandle ProcessHandle, SafeKernelObjectHandle DebugHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateDebugObject(out SafeKernelObjectHandle DebugHandle, DebugAccessRights DesiredAccess, [In] ObjectAttributes ObjectAttributes, int Flags);
    }
#pragma warning restore 1591

    /// <summary>
    /// Class representing a NT Debug object
    /// </summary>
    public class NtDebug : NtObjectWithDuplicate<NtDebug, GenericAccessRights>
    {
        internal NtDebug(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        /// <summary>
        /// Create a debug object
        /// </summary>
        /// <param name="name">The debug object name (can be null)</param>
        /// <param name="root">The root directory for relative names</param>
        /// <returns>The debug object</returns>
        public static NtDebug Create(string name, NtObject root)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, DebugAccessRights.MaximumAllowed);
            }
        }

        /// <summary>
        /// Create a debug object
        /// </summary>
        /// <param name="desired_access">Desired access for the debug object</param>
        /// <param name="object_attributes">Object attributes for debug object</param>
        /// <returns>The debug object</returns>
        public static NtDebug Create(ObjectAttributes object_attributes, DebugAccessRights desired_access)
        {
            SafeKernelObjectHandle handle;
            NtSystemCalls.NtCreateDebugObject(out handle, desired_access, object_attributes, 0).ToNtException();
            return new NtDebug(handle);
        }

        /// <summary>
        /// Create a debug object
        /// </summary>
        /// <returns>The debug object</returns>
        public static NtDebug Create()
        {
            return Create(null, null);
        }
    }
}
