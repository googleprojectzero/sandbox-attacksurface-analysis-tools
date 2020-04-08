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
    /// Tree security mode.
    /// </summary>
    public enum TreeSecInfo
    {
        Set = 1,
        Reset = 2,
        ResetKeepExplicit = 3
    }

    /// <summary>
    /// Progress invoke setting for tree security.
    /// </summary>
    public enum ProgressInvokeSetting
    {
        InvokeNever = 1,
        EveryObject,
        OnError,
        CancelOperation,
        RetryOperation,
        PrePostError
    }

    /// <summary>
    /// Progress function for tree named security info.
    /// </summary>
    /// <param name="object_name">The name of the object.</param>
    /// <param name="status">The operation status.</param>
    /// <param name="invoke_setting">The current invoke setting.</param>
    /// <param name="security_set">True if security is set.</param>
    /// <returns>The invoke setting. Return original invoke_setting if no change.</returns>
    public delegate ProgressInvokeSetting TreeProgressFunction(string object_name, Win32Error status,
        ProgressInvokeSetting invoke_setting, bool security_set);

#pragma warning restore 1591

    /// <summary>
    /// Security utilities which call the Win32 APIs.
    /// </summary>
    public static class Win32Security
    {
        #region Static Methods
        /// <summary>
        /// Set security using a named object.
        /// </summary>
        /// <param name="name">The name of the object.</param>
        /// <param name="type">The type of named object.</param>
        /// <param name="security_information">The security information to set.</param>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus SetSecurityInfo(string name, SeObjectType type, 
            SecurityInformation security_information, 
            SecurityDescriptor security_descriptor, bool throw_on_error)
        {
            return Win32NativeMethods.SetNamedSecurityInfo(
                name, type, security_information, 
                security_descriptor.Owner?.Sid.ToArray(),
                security_descriptor.Group?.Sid.ToArray(), 
                security_descriptor.Dacl?.ToByteArray(),
                security_descriptor.Sacl?.ToByteArray()).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Set security using a named object.
        /// </summary>
        /// <param name="name">The name of the object.</param>
        /// <param name="type">The type of named object.</param>
        /// <param name="security_information">The security information to set.</param>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <param name="invoke_setting">Specify to indicate when to execute progress function.</param>
        /// <param name="action">The security operation to perform on the tree.</param>
        /// <param name="progress_function">Progress function.</param>
        public static void SetSecurityInfo(string name, SeObjectType type,
            SecurityInformation security_information,
            SecurityDescriptor security_descriptor,
            TreeSecInfo action,
            TreeProgressFunction progress_function,
            ProgressInvokeSetting invoke_setting
            )
        {
            SetSecurityInfo(name, type, security_information, security_descriptor, action, progress_function, invoke_setting, true);
        }

        /// <summary>
        /// Set security using a named object.
        /// </summary>
        /// <param name="name">The name of the object.</param>
        /// <param name="type">The type of named object.</param>
        /// <param name="security_information">The security information to set.</param>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <param name="invoke_setting">Specify to indicate when to execute progress function.</param>
        /// <param name="action">The security operation to perform on the tree.</param>
        /// <param name="progress_function">Progress function.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus SetSecurityInfo(string name, SeObjectType type,
            SecurityInformation security_information,
            SecurityDescriptor security_descriptor,
            TreeSecInfo action,
            TreeProgressFunction progress_function,
            ProgressInvokeSetting invoke_setting,
            bool throw_on_error)
        {
            return Win32NativeMethods.TreeSetNamedSecurityInfo(
                name, type, security_information,
                security_descriptor.Owner?.Sid.ToArray(),
                security_descriptor.Group?.Sid.ToArray(),
                security_descriptor.Dacl?.ToByteArray(),
                security_descriptor.Sacl?.ToByteArray(),
                action,
                CreateCallback(progress_function),
                invoke_setting,
                IntPtr.Zero
                ).ToNtException(throw_on_error);
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
        /// <returns>The NT status code.</returns>
        public static NtStatus SetSecurityInfo(SafeHandle handle, SeObjectType type,
            SecurityInformation security_information,
            SecurityDescriptor security_descriptor, bool throw_on_error)
        {
            return Win32NativeMethods.SetSecurityInfo(
                handle, type, security_information,
                security_descriptor.Owner?.Sid.ToArray(),
                security_descriptor.Group?.Sid.ToArray(),
                security_descriptor.Dacl?.ToByteArray(),
                security_descriptor.Sacl?.ToByteArray())
                .ToNtException(throw_on_error);
        }

        /// <summary>
        /// Set security using an object handle.
        /// </summary>
        /// <param name="handle">The handle of the object.</param>
        /// <param name="type">The type of object.</param>
        /// <param name="security_information">The security information to set.</param>
        /// <param name="security_descriptor">The security descriptor to set.</param>
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
        /// <returns>The NT status code.</returns>
        public static NtStatus SetSecurityInfo(NtObject obj, SeObjectType type,
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
        public static void SetSecurityInfo(NtObject obj, SeObjectType type,
            SecurityInformation security_information,
            SecurityDescriptor security_descriptor)
        {
            SetSecurityInfo(obj, type, security_information, security_descriptor, true);
        }

        /// <summary>
        /// Reset security using a named object.
        /// </summary>
        /// <param name="name">The name of the object.</param>
        /// <param name="type">The type of named object.</param>
        /// <param name="security_information">The security information to set.</param>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <param name="keep_explicit">True to keep explicit ACEs.</param>
        /// <param name="invoke_setting">Specify to indicate when to execute progress function.</param>

        /// <param name="progress_function">Progress function.</param>
        public static void ResetSecurityInfo(string name, SeObjectType type,
            SecurityInformation security_information,
            SecurityDescriptor security_descriptor,
            TreeProgressFunction progress_function,
            ProgressInvokeSetting invoke_setting,
            bool keep_explicit
            )
        {
            ResetSecurityInfo(name, type, security_information, security_descriptor, 
                progress_function, invoke_setting, keep_explicit, true);
        }

        /// <summary>
        /// Reset security using a named object.
        /// </summary>
        /// <param name="name">The name of the object.</param>
        /// <param name="type">The type of named object.</param>
        /// <param name="security_information">The security information to set.</param>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <param name="invoke_setting">Specify to indicate when to execute progress function.</param>
        /// <param name="keep_explicit">True to keep explicit ACEs.</param>
        /// <param name="progress_function">Progress function.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus ResetSecurityInfo(string name, SeObjectType type,
            SecurityInformation security_information,
            SecurityDescriptor security_descriptor,
            TreeProgressFunction progress_function,
            ProgressInvokeSetting invoke_setting,
            bool keep_explicit,
            bool throw_on_error)
        {
            return Win32NativeMethods.TreeResetNamedSecurityInfo(
                name, type, security_information,
                security_descriptor.Owner?.Sid.ToArray(),
                security_descriptor.Group?.Sid.ToArray(),
                security_descriptor.Dacl?.ToByteArray(),
                security_descriptor.Sacl?.ToByteArray(),
                keep_explicit,
                CreateCallback(progress_function),
                invoke_setting,
                IntPtr.Zero
                ).ToNtException(throw_on_error);
        }
        #endregion

        #region Private Members
        private static TreeSetNamedSecurityProgress CreateCallback(TreeProgressFunction progress_function)
        {
            if (progress_function != null)
            {
                return (string n, Win32Error s,
                    ref ProgressInvokeSetting p, IntPtr a, bool t)
                        => p = progress_function(n, s, p, t);
            }
            return null;
        }
        #endregion
    }
}
