//  Copyright 2017 Google Inc. All Rights Reserved.
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
    public enum SessionAccessRights : uint
    {
        Query = 0x0001,
        Modify = 0x0002,
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
        public static extern NtStatus NtOpenSession(out SafeKernelObjectHandle Handle,
            SessionAccessRights DesiredAccess, [In]ObjectAttributes ObjectAttributes);
    }
#pragma warning restore 1591

    /// <summary>
    /// Class to represent a Session object
    /// </summary>
    [NtType("Session")]
    public class NtSession : NtObjectWithDuplicate<NtSession, SessionAccessRights>
    {
        internal NtSession(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        internal sealed class NtTypeFactoryImpl : NtTypeFactoryImplBase
        {
            public NtTypeFactoryImpl() : base(true)
            {
            }

            protected override sealed NtResult<NtSession> OpenInternal(ObjectAttributes obj_attributes,
                SessionAccessRights desired_access, bool throw_on_error)
            {
                return NtSession.Open(obj_attributes, desired_access, throw_on_error);
            }
        }

        /// <summary>
        /// Open a session object.
        /// </summary>
        /// <param name="obj_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the object</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The open result.</returns>
        public static NtResult<NtSession> Open(ObjectAttributes obj_attributes, SessionAccessRights desired_access, bool throw_on_error)
        {
            return NtSystemCalls.NtOpenSession(out SafeKernelObjectHandle handle,
                desired_access, obj_attributes).CreateResult(throw_on_error, () => new NtSession(handle));
        }

        /// <summary>
        /// Open a session object.
        /// </summary>
        /// <param name="obj_attributes">The object attributes</param>
        /// <param name="desired_access">Desired access for the object</param>
        /// <returns>The open result.</returns>
        public static NtSession Open(ObjectAttributes obj_attributes, SessionAccessRights desired_access)
        {
            return Open(obj_attributes, desired_access, true).Result;
        }

        /// <summary>
        /// Open a session object.
        /// </summary>
        /// <param name="name">Name of the object</param>
        /// <param name="root">Optional root directory for lookup</param>
        /// <param name="desired_access">Desired access for the object</param>
        /// <returns>The open result.</returns>
        public static NtSession Open(string name, NtObject root, SessionAccessRights desired_access)
        {
            using (var obja = new ObjectAttributes(name, AttributeFlags.CaseInsensitive, root))
            {
                return Open(obja, desired_access);
            }
        }
    }
}
