//  Copyright 2022 Google LLC. All Rights Reserved.
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

namespace NtApiDotNet.Win32.Security.Credential.CredUI
{
    /// <summary>
    /// Class to represent a Windows credential prompt.
    /// </summary>
    public sealed class WindowsCredentialPromptDialog : CredentialPromptDialog
    {
        /// <summary>
        /// Specify the input authentication buffer.
        /// </summary>
        public CredentialAuthenticationBuffer InputAuthBuffer { get; set; }

        /// <summary>
        /// Specify flags for the prompt.
        /// </summary>
        public WindowsCredentialPromptDialogFlags Flags { get; set; }

        /// <summary>
        /// Show the credential prompt.
        /// </summary>
        /// <returns>The result of the credential prompt.</returns>
        /// <remarks>If the dialog is cancelled this will return successfully but the Cancelled property will be set to true.</remarks>
        public NtResult<WindowsCredentialPromptResult> Show(bool throw_on_error)
        {
            byte[] input_auth_buffer = InputAuthBuffer?.ToArray();
            int input_auth_buffer_len = input_auth_buffer?.Length ?? 0;
            int save = Save ? 1 : 0;
            if (Package is null)
                throw new ArgumentNullException("AuthPackage cannot be null.", nameof(Package));

            uint package_id = Package.PackageId;
            var result = SecurityNativeMethods.CredUIPromptForWindowsCredentials(
                CreateCredUiInfo(), AuthError, ref package_id,
                input_auth_buffer, input_auth_buffer_len, out SafeCoTaskMemBuffer buffer, out int buffer_size, ref save, (uint)Flags);
            if (result == Win32Error.ERROR_CANCELLED)
               return new WindowsCredentialPromptResult(package_id).CreateResult();
            return result.CreateWin32Result(throw_on_error, () =>
            {
                using (buffer)
                {
                    buffer.InitializeLength(buffer_size);
                    return new WindowsCredentialPromptResult(new CredentialAuthenticationBuffer(buffer.ToArray()),
                        save, package_id);
                }
            });
        }

        /// <summary>
        /// Show the credential prompt.
        /// </summary>
        /// <returns>The result of the credential prompt.</returns>
        /// <remarks>If the dialog is cancelled this will return successfully but the Cancelled property will be set to true.</remarks>
        public WindowsCredentialPromptResult Show()
        {
            return Show(true).Result;
        }
    }
}
