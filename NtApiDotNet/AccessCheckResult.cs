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
using System.Collections.Generic;

namespace NtApiDotNet
{
    /// <summary>
    /// Result of an access check with specific access types.
    /// </summary>
    /// <typeparam name="T">The access rights type, must be derived from an Enum.</typeparam>
    public class AccessCheckResult<T> where T : Enum
    {
        /// <summary>
        /// The NT status code from the access check.
        /// </summary>
        public NtStatus Status { get; }
        /// <summary>
        /// The granted access mask from the check.
        /// </summary>
        public AccessMask GrantedAccess { get; }
        /// <summary>
        /// The granted access mapped to generic access mask.
        /// </summary>
        public AccessMask GenericGrantedAccess { get; }
        /// <summary>
        /// The required privileges for this access.
        /// </summary>
        public IEnumerable<TokenPrivilege> PrivilegesRequired { get; }
        /// <summary>
        /// The specific granted access mask from the check.
        /// </summary>
        public T SpecificGrantedAccess { get; }
        /// <summary>
        /// The specific granted access mapped to generic access mask.
        /// </summary>
        public T SpecificGenericGrantedAccess { get; }
        /// <summary>
        /// Object type associated with the access.
        /// </summary>
        public Guid ObjectType { get; }
        /// <summary>
        /// Optional name for the object type.
        /// </summary>
        public string Name { get; private set; }
        /// <summary>
        /// When a result from an Audit Access Check indicates whether the
        /// an audit needs to be generated on close.
        /// </summary>
        public bool GenerateOnClose { get; internal set; }

        /// <summary>
        /// Whether the access check was a success.
        /// </summary>
        public bool IsSuccess => Status.IsSuccess();
        /// <summary>
        /// Get access check result as a specific access.
        /// </summary>
        /// <returns>The specific access results.</returns>
        public AccessCheckResult<U> ToSpecificAccess<U>() where U : Enum
        {
            return new AccessCheckResult<U>(Status, GrantedAccess, GenericGrantedAccess, PrivilegesRequired, 
                GrantedAccess.ToSpecificAccess<U>(), GenericGrantedAccess.ToSpecificAccess<U>(), 
                ObjectType, Name, GenerateOnClose);
        }
        /// <summary>
        /// Get access check result as a specific access.
        /// </summary>
        /// <returns>The specific access.</returns>
        public AccessCheckResultGeneric ToSpecificAccess(Type specific_access_type)
        {
            return new AccessCheckResultGeneric(Status, GrantedAccess, GenericGrantedAccess, PrivilegesRequired,
                GrantedAccess.ToSpecificAccess(specific_access_type),
                GenericGrantedAccess.ToSpecificAccess(specific_access_type), 
                ObjectType, Name, GenerateOnClose);
        }

        internal AccessCheckResult(NtStatus status,
            AccessMask granted_access,
            AccessMask generic_granted_access,
            IEnumerable<TokenPrivilege> privilege_required,
            ObjectTypeEntry object_type,
            bool generate_on_close) 
            : this(status, granted_access, 
                  generic_granted_access, privilege_required,
                  granted_access.ToSpecificAccess<T>(),
                  generic_granted_access.ToSpecificAccess<T>(),
                  object_type.ObjectType, 
                  object_type.Name, 
                  generate_on_close)
        {
        }

        internal AccessCheckResult(NtStatus status,
            AccessMask granted_access,
            AccessMask generic_granted_access,
            IEnumerable<TokenPrivilege> privilege_required,
            T specific_granted_access,
            T specific_generic_granted_access,
            Guid object_type,
            string object_type_name,
            bool generate_on_close)
        {
            Status = status;
            GrantedAccess = granted_access;
            GenericGrantedAccess = generic_granted_access;
            PrivilegesRequired = privilege_required;
            SpecificGrantedAccess = specific_granted_access;
            SpecificGenericGrantedAccess = specific_generic_granted_access;
            ObjectType = object_type;
            Name = object_type_name ?? string.Empty;
            GenerateOnClose = generate_on_close;
        }
    }

    /// <summary>
    /// Result of an access check.
    /// </summary>
    public class AccessCheckResult : AccessCheckResult<GenericAccessRights>
    {
        internal AccessCheckResult(NtStatus status,
            AccessMask granted_access,
            SafePrivilegeSetBuffer privilege_set,
            GenericMapping generic_mapping,
            ObjectTypeEntry object_type,
            bool generate_on_close)
            : this(status, granted_access,
                  generic_mapping.UnmapMask(granted_access),
                  privilege_set?.GetPrivileges() ?? new TokenPrivilege[0],
                  object_type?.ObjectType ?? Guid.Empty, object_type?.Name, generate_on_close)
        {
        }

        internal AccessCheckResult(
            NtStatus status,
            AccessMask granted_access,
            AccessMask generic_granted_access,
            IEnumerable<TokenPrivilege> privilege_required,
            Guid object_type,
            string object_type_name,
            bool generate_on_close)
            : base(status, granted_access, generic_granted_access, privilege_required,
                  granted_access.ToGenericAccess(), generic_granted_access.ToGenericAccess(),
                  object_type, object_type_name, generate_on_close)
        {
        }
    }

    /// <summary>
    /// Result of an access check with generic Enum access types.
    /// </summary>
    public class AccessCheckResultGeneric : AccessCheckResult<Enum>
    {
        internal AccessCheckResultGeneric(NtStatus status,
            AccessMask granted_access,
            AccessMask generic_granted_access,
            IEnumerable<TokenPrivilege> privilege_required,
            Enum specific_granted_access,
            Enum specific_generic_granted_access,
            Guid object_type,
            string object_type_name,
            bool generate_on_close) : base(status, granted_access,
                generic_granted_access, privilege_required,
                specific_granted_access, specific_generic_granted_access,
                object_type, object_type_name, generate_on_close)
        {
        }
    }
}