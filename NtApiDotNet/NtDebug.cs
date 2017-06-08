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

    [Flags]
    public enum DebugObjectFlags
    {
        None = 0,
        Unknown1 = 1,
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtDebugActiveProcess(SafeKernelObjectHandle ProcessHandle, SafeKernelObjectHandle DebugHandle);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateDebugObject(out SafeKernelObjectHandle DebugHandle, 
            DebugAccessRights DesiredAccess, [In] ObjectAttributes ObjectAttributes, DebugObjectFlags Flags);
    }
#pragma warning restore 1591

    /// <summary>
    /// Class representing a NT Debug object
    /// </summary>
    [NtType("DebugObject")]
    public class NtDebug : NtObjectWithDuplicate<NtDebug, DebugAccessRights>
    {
        internal NtDebug(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        /// <summary>
        /// Create a debug object
        /// </summary>
        /// <param name="name">The debug object name (can be null)</param>
        /// <param name="root">The root directory for relative names</param>
        /// <param name="flags">Debug object flags.</param>
        /// <returns>The debug object</returns>
        public static NtDebug Create(string name, NtObject root, DebugObjectFlags flags)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                return Create(obja, DebugAccessRights.MaximumAllowed, DebugObjectFlags.None);
            }
        }

        /// <summary>
        /// Create a debug object
        /// </summary>
        /// <param name="desired_access">Desired access for the debug object</param>
        /// <param name="object_attributes">Object attributes for debug object</param>
        /// <param name="flags">Debug object flags.</param>
        /// <returns>The debug object</returns>
        public static NtDebug Create(ObjectAttributes object_attributes, DebugAccessRights desired_access, DebugObjectFlags flags)
        {
            return Create(object_attributes, desired_access, flags, true).Result;
        }

        /// <summary>
        /// Create a debug object
        /// </summary>
        /// <param name="desired_access">Desired access for the debug object</param>
        /// <param name="object_attributes">Object attributes for debug object</param>
        /// <param name="flags">Debug object flags.</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtDebug> Create(ObjectAttributes object_attributes, DebugAccessRights desired_access, DebugObjectFlags flags, bool throw_on_error)
        {
            SafeKernelObjectHandle handle;
            return NtSystemCalls.NtCreateDebugObject(out handle, desired_access, object_attributes, flags).CreateResult(throw_on_error, () => new NtDebug(handle));
        }

        /// <summary>
        /// Create a debug object
        /// </summary>
        /// <returns>The debug object</returns>
        public static NtDebug Create()
        {
            return Create(null, null, DebugObjectFlags.None);
        }

        /// <summary>
        /// Open a named debug object
        /// </summary>
        /// <param name="name">The debug object name </param>
        /// <param name="root">The root directory for relative names</param>
        /// <param name="desired_access">Desired access for the debug object</param>
        /// <returns>The debug object</returns>
        public static NtDebug Open(string name, NtObject root, DebugAccessRights desired_access)
        {
            using (ObjectAttributes obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive | AttributeFlags.OpenIf, root))
            {
                return Create(obja, DebugAccessRights.MaximumAllowed, DebugObjectFlags.None);
            }
        }

        /// <summary>
        /// Open a named debug object
        /// </summary>
        /// <param name="object_attributes">The object attributes to open.</param>
        /// <param name="desired_access">Desired access for the debug object</param>
        /// <returns>The debug object</returns>
        public static NtDebug Open(ObjectAttributes object_attributes, DebugAccessRights desired_access)
        {
            return Create(object_attributes, DebugAccessRights.MaximumAllowed, DebugObjectFlags.None, true).Result;
        }

        /// <summary>
        /// Open a named debug object
        /// </summary>
        /// <param name="object_attributes">The object attributes to open.</param>
        /// <param name="desired_access">Desired access for the debug object</param>
        /// <param name="throw_on_error">True to throw an exception on error.</param>
        /// <returns>The NT status code and object result.</returns>
        public static NtResult<NtDebug> Open(ObjectAttributes object_attributes, DebugAccessRights desired_access, bool throw_on_error)
        {
            return Create(object_attributes, DebugAccessRights.MaximumAllowed, DebugObjectFlags.None, throw_on_error);
        }

        internal static NtResult<NtObject> FromName(ObjectAttributes object_attributes, AccessMask desired_access, bool throw_on_error)
        {
            return Open(object_attributes, desired_access.ToSpecificAccess<DebugAccessRights>(), throw_on_error).Cast<NtObject>();
        }
    }
}
