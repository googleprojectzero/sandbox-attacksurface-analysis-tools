//  Copyright 2021 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Win32.SafeHandles;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Collections.Generic;

namespace NtApiDotNet.Win32.Security.Sam
{
    internal static class SamUtils
    {
        public const string SAM_SERVER_NT_TYPE_NAME = "SamServer";

        public static GenericMapping GetSamServerGenericMapping()
        {
            return new GenericMapping()
            {
                GenericRead = SamServerAccessRights.ReadControl | SamServerAccessRights.EnumerateDomains,
                GenericWrite = SamServerAccessRights.ReadControl | SamServerAccessRights.Shutdown | SamServerAccessRights.Initialize | SamServerAccessRights.CreateDomain,
                GenericExecute = SamServerAccessRights.ReadControl | SamServerAccessRights.Connect | SamServerAccessRights.LookupDomain,
                GenericAll = SamServerAccessRights.ReadControl | SamServerAccessRights.WriteDac | SamServerAccessRights.WriteOwner | SamServerAccessRights.Delete |
                    SamServerAccessRights.EnumerateDomains | SamServerAccessRights.Shutdown | SamServerAccessRights.Initialize | SamServerAccessRights.CreateDomain |
                    SamServerAccessRights.Connect | SamServerAccessRights.LookupDomain
            };
        }

        public static NtResult<IReadOnlyList<T>> SamEnumerateObjects<T, S>(SafeSamHandle handle,
                SecurityEnumDelegate<SafeSamHandle, SafeSamMemoryBuffer> func, Func<S, T> select_object,
                bool throw_on_error) where S : struct
        {
            return SecurityNativeMethods.EnumerateObjects(handle, func, select_object, throw_on_error);
        }
    }
}
