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

using NtApiDotNet.Utilities.Reflection;
using System;

namespace NtApiDotNet.Win32.Security.Credential.CredUI
{
    /// <summary>
    /// Flags for the Windows credential prompt.
    /// </summary>
    [Flags]
    public enum WindowsCredentialPromptDialogFlags : uint
    {
        /// <summary>
        /// None.
        /// </summary>
        None = 0,
        /// <summary>
        /// Plain text username/password is being requested
        /// </summary>
        [SDKName("CREDUIWIN_GENERIC")]
        Generic = 0x00000001,
        /// <summary>
        /// Show the Save Credential checkbox
        /// </summary>
        [SDKName("CREDUIWIN_CHECKBOX")]
        Checkbox = 0x00000002,
        /// <summary>
        /// Only Cred Providers that support the input auth package should enumerate.
        /// </summary>
        [SDKName("CREDUIWIN_AUTHPACKAGE_ONLY")]
        AuthPackageOnly = 0x00000010,
        /// <summary>
        /// Only the incoming cred for the specific auth package should be enumerated.
        /// </summary>
        [SDKName("CREDUIWIN_IN_CRED_ONLY")]
        InCredOnly = 0x00000020,
        /// <summary>
        /// Cred Providers should enumerate administrators only.
        /// </summary>
        [SDKName("CREDUIWIN_ENUMERATE_ADMINS")]
        EnumerateAdmins = 0x00000100,
        /// <summary>
        /// Only the incoming cred for the specific auth package should be enumerated.
        /// </summary>
        [SDKName("CREDUIWIN_ENUMERATE_CURRENT_USER")]
        EnumerateCurrentUser = 0x00000200,
        /// <summary>
        /// The Credui prompt should be displayed on the secure desktop.
        /// </summary>
        [SDKName("CREDUIWIN_SECURE_PROMPT")]
        SecurePrompt = 0x00001000,
        /// <summary>
        /// CredUI is invoked by SspiPromptForCredentials and the client is prompting before a prior handshake
        /// </summary>
        [SDKName("CREDUIWIN_PREPROMPTING")]
        PrePrompting = 0x00002000,
        /// <summary>
        /// The credential provider will not pack the AAD authority name.
        /// </summary>
        DontPackAADAuthority = 0x00004000,
        /// <summary>
        /// Tell the credential provider it should be packing its Auth Blob 32 bit even though it is running 64 native
        /// </summary>
        [SDKName("CREDUIWIN_PACK_32_WOW")]
        Pack32Wow = 0x10000000,
        /// <summary>
        /// Windows Hello credentials will be packed in a smart card auth buffer.
        /// </summary>
        PackHelloAsSmartCard = 0x80000000,
    }
}
