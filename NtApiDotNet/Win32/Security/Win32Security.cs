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

using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security
{
#pragma warning disable 1591
    /// <summary>
    /// Enumeration for object type.
    /// </summary>
    public enum SeObjectType
    {
        Unknown = 0,
        File,
        Service,
        Printer,
        RegistryKey,
        LMShare,
        Kernel,
        Window,
        Ds,
        DsAll,
        ProviderDefined,
        WmiGuid,
        RegistryWow6432Key,
        RegistryWow6464Key
    }

    /// <summary>
    /// Security utilities which call the Win32 APIs.
    /// </summary>
    public static class Win32Security
    {
        /// <summary>
        /// Set security using a named object.
        /// </summary>
        /// <param name="name">The name of the object.</param>
        /// <param name="type">The type of named object.</param>
        /// <param name="security_information">The security information to set.</param>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The Win32 Error Code.</returns>
        public static Win32Error SetSecurityInfo(string name, SeObjectType type, 
            SecurityInformation security_information, 
            SecurityDescriptor security_descriptor, bool throw_on_error)
        {
            var error = Win32NativeMethods.SetNamedSecurityInfo(name, type, security_information, security_descriptor.Owner?.Sid.ToArray(),
                security_descriptor.Group?.Sid.ToArray(), security_descriptor.Dacl?.ToByteArray(),
                security_descriptor.Sacl?.ToByteArray());
            error.ToNtException(throw_on_error);
            return error;
        }

        /// <summary>
        /// Set security using a named object.
        /// </summary>
        /// <param name="name">The name of the object.</param>
        /// <param name="type">The type of named object.</param>
        /// <param name="security_information">The security information to set.</param>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <returns>The Win32 Error Code.</returns>
        public static void SetSecurityInfo(string name, SeObjectType type,
            SecurityInformation security_information,
            SecurityDescriptor security_descriptor)
        {
            SetSecurityInfo(name, type, security_information, security_descriptor, true);
        }

        /// <summary>
        /// Set security using an object handle.
        /// </summary>
        /// <param name="handle">The handle of the object.</param>
        /// <param name="type">The type of object.</param>
        /// <param name="security_information">The security information to set.</param>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The Win32 Error Code.</returns>
        public static Win32Error SetSecurityInfo(SafeHandle handle, SeObjectType type,
            SecurityInformation security_information,
            SecurityDescriptor security_descriptor, bool throw_on_error)
        {
            var error = Win32NativeMethods.SetSecurityInfo(handle, type, security_information, security_descriptor.Owner?.Sid.ToArray(),
                security_descriptor.Group?.Sid.ToArray(), security_descriptor.Dacl?.ToByteArray(),
                security_descriptor.Sacl?.ToByteArray());
            error.ToNtException(throw_on_error);
            return error;
        }

        /// <summary>
        /// Set security using an object handle.
        /// </summary>
        /// <param name="handle">The handle of the object.</param>
        /// <param name="type">The type of object.</param>
        /// <param name="security_information">The security information to set.</param>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <returns>The Win32 Error Code.</returns>
        public static void SetSecurityInfo(SafeHandle handle, SeObjectType type,
            SecurityInformation security_information,
            SecurityDescriptor security_descriptor)
        {
            SetSecurityInfo(handle, type, security_information, security_descriptor, true);
        }

        /// <summary>
        /// Set security using an object handle.
        /// </summary>
        /// <param name="obj">The handle of the object.</param>
        /// <param name="type">The type of object.</param>
        /// <param name="security_information">The security information to set.</param>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The Win32 Error Code.</returns>
        public static Win32Error SetSecurityInfo(NtObject obj, SeObjectType type,
            SecurityInformation security_information,
            SecurityDescriptor security_descriptor, bool throw_on_error)
        {
            return SetSecurityInfo(obj.Handle, type, security_information, security_descriptor, throw_on_error);
        }

        /// <summary>
        /// Set security using an object handle.
        /// </summary>
        /// <param name="obj">The handle of the object.</param>
        /// <param name="type">The type of object.</param>
        /// <param name="security_information">The security information to set.</param>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <returns>The Win32 Error Code.</returns>
        public static void SetSecurityInfo(NtObject obj, SeObjectType type,
            SecurityInformation security_information,
            SecurityDescriptor security_descriptor)
        {
            SetSecurityInfo(obj, type, security_information, security_descriptor, true);
        }
    }
#pragma warning restore 1591
}
