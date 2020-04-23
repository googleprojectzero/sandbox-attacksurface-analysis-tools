//  Copyright 2020 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet.Win32.Security.Authorization
{
    /// <summary>
    /// Access check result from AuthZ.
    /// </summary>
    public class AuthZAccessCheckResult : AccessCheckResultGeneric
    {
        /// <summary>
        /// The Win32 error code from the access check.
        /// </summary>
        public Win32Error Error { get; }

        internal AuthZAccessCheckResult(
            NtType type,
            Win32Error error,
            AccessMask granted_access,
            ObjectTypeEntry object_type) : base(error.MapDosErrorToStatus(),
                granted_access, type.GenericMapping.UnmapMask(granted_access),
                new TokenPrivilege[0], granted_access.ToSpecificAccess(type.AccessRightsType),
                type.GenericMapping.UnmapMask(granted_access).ToSpecificAccess(type.AccessRightsType),
                object_type?.ObjectType ?? Guid.Empty, object_type?.Name ?? string.Empty, false)
        {
            Error = error;
        }
    }
}
