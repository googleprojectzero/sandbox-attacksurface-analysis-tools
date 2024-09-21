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

namespace NtApiDotNet.Security
{
    /// <summary>
    /// Interface for an NT object to query and set a security descriptor.
    /// </summary>
    public interface INtObjectSecurity
    {
        /// <summary>
        /// Get the name of the object.
        /// </summary>
        string ObjectName { get; }

        /// <summary>
        /// Get the NtType for this object.
        /// </summary>
        /// <returns>The NtType for the object.</returns>
        NtType NtType { get; }

        /// <summary>
        /// Get the object's security descriptor.
        /// </summary>
        SecurityDescriptor SecurityDescriptor { get; }

        /// <summary>
        /// Get whether the object is a container.
        /// </summary>
        bool IsContainer { get; }

        /// <summary>
        /// Check if access is granted to a set of rights
        /// </summary>
        /// <param name="access">The access rights to check</param>
        /// <returns>True if all the access rights are granted</returns>
        bool IsAccessMaskGranted(AccessMask access);

        /// <summary>
        /// Set the object's security descriptor
        /// </summary>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <param name="security_information">What parts of the security descriptor to set</param>
        void SetSecurityDescriptor(SecurityDescriptor security_descriptor, SecurityInformation security_information);

        /// <summary>
        /// Set the object's security descriptor
        /// </summary>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <param name="security_information">What parts of the security descriptor to set</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        NtStatus SetSecurityDescriptor(SecurityDescriptor security_descriptor, SecurityInformation security_information, bool throw_on_error);

        /// <summary>
        /// Get the security descriptor specifying which parts to retrieve
        /// </summary>
        /// <param name="security_information">What parts of the security descriptor to retrieve</param>
        /// <returns>The security descriptor</returns>
        SecurityDescriptor GetSecurityDescriptor(SecurityInformation security_information);

        /// <summary>
        /// Get the security descriptor specifying which parts to retrieve
        /// </summary>
        /// <param name="security_information">What parts of the security descriptor to retrieve</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The security descriptor</returns>
        NtResult<SecurityDescriptor> GetSecurityDescriptor(SecurityInformation security_information, bool throw_on_error);
    }
}
