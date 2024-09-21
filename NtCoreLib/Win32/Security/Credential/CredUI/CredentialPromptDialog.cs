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

using NtCoreLib.Win32.Security.Authentication;
using NtCoreLib.Win32.Security.Interop;
using System;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Security.Credential.CredUI;

/// <summary>
/// Base class to represent a credential UI prompt.
/// </summary>
public abstract class CredentialPromptDialog
{
    /// <summary>
    /// Message text for UI.
    /// </summary>
    public string MessageText { get; set; }
    /// <summary>
    /// Caption text.
    /// </summary>
    public string CaptionText { get; set; }
    /// <summary>
    /// Parent HWND.
    /// </summary>
    public IntPtr HwndParent { get; set; }
    /// <summary>
    /// Bitmap for banner.
    /// </summary>
    public IntPtr HbmBanner { get; set; }
    /// <summary>
    /// Specify the last authentication error.
    /// </summary>
    public Win32Error AuthError { get; set; }
    /// <summary>
    /// Specify whether to check the save credentials box.
    /// </summary>
    public bool Save { get; set; }
    /// <summary>
    /// Specify the input package for the credentials.
    /// </summary>
    public AuthenticationPackage Package { get; set; }

    private protected CREDUI_INFO CreateCredUiInfo()
    {
        return new CREDUI_INFO()
        {
            cbSize = Marshal.SizeOf<CREDUI_INFO>(),
            hwndParent = HwndParent,
            pszMessageText = MessageText,
            pszCaptionText = CaptionText,
            hbmBanner = HbmBanner
        };
    }

    private protected CredentialPromptDialog()
    {
        MessageText = string.Empty;
        CaptionText = string.Empty;
    }
}
