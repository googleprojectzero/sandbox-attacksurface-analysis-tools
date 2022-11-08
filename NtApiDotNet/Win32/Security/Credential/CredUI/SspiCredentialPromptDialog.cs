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
using NtApiDotNet.Win32.Security.Credential.AuthIdentity;
using NtApiDotNet.Win32.Security.Native;
using System;

namespace NtApiDotNet.Win32.Security.Credential.CredUI
{
    /// <summary>
    /// Class to represent an SSPI credential prompt.
    /// </summary>
    public sealed class SspiCredentialPromptDialog : CredentialPromptDialog
    {
        /// <summary>
        /// Specify the target name.
        /// </summary>
        public string TargetName { get; set; }

        /// <summary>
        /// Specify the input authentication identity.
        /// </summary>
        public SecWinNtAuthIdentity InputAuthIdentity { get; set; }

        /// <summary>
        /// Specify flags for the prompt.
        /// </summary>
        public SspiCredentialPromptDialogFlags Flags { get; set; }

        /// <summary>
        /// Show the credential prompt.
        /// </summary>
        /// <returns>The result of the credential prompt.</returns>
        /// <remarks>If the dialog is cancelled this will return successfully but the Cancelled property will be set to true.</remarks>
        public NtResult<SspiCredentialPromptResult> Show(bool throw_on_error)
        {
            if (Package is null)
                throw new ArgumentNullException("Must specify an authentication package.", nameof(Package));
            using (var input_auth = InputAuthIdentity?.Copy()?.DangerousBuffer ?? SafeSecWinNtAuthIdentityBuffer.Null)
            {
                int save = Save ? 1 : 0;
                var result = SecurityNativeMethods.SspiPromptForCredentials(TargetName, CreateCredUiInfo(), AuthError, Package.Name,
                    input_auth, out SafeSecWinNtAuthIdentityBuffer auth_id, ref save, (int)Flags);
                if (result == Win32Error.ERROR_CANCELLED)
                    return new SspiCredentialPromptResult(Package).CreateResult();
                return result.CreateWin32Result(throw_on_error, () => new SspiCredentialPromptResult(auth_id, save, Package));
            }
        }

        /// <summary>
        /// Show the credential prompt.
        /// </summary>
        /// <returns>The result of the credential prompt.</returns>
        /// <remarks>If the dialog is cancelled this will return successfully but the Cancelled property will be set to true.</remarks>
        public SspiCredentialPromptResult Show()
        {
            return Show(true).Result;
        }
    }
}
