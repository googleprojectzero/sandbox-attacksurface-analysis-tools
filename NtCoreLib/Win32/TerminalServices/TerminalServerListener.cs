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

#nullable enable

using NtCoreLib.Security.Authorization;
using NtCoreLib.Win32.TerminalServices.Interop;
using System;

namespace NtCoreLib.Win32.TerminalServices;

/// <summary>
/// Class to represent a terminal server listener.
/// </summary>
public sealed class TerminalServerListener
{
    #region Internal Members
    internal TerminalServerListener(WTSLISTENERNAME name)
    {
        Name = name.GetName();
    }
    #endregion

    #region Public Properties
    /// <summary>
    /// Get the name of the listener.
    /// </summary>
    public string Name { get; }
    #endregion

    #region Public Methods
    /// <summary>
    /// Get the security descriptor for the listener.
    /// </summary>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The listener security descriptor.</returns>
    public NtResult<SecurityDescriptor> GetSecurityDescriptor(bool throw_on_error)
    {
        int length_needed = 1024;
        for (int i = 0; i < 2; i++)
        {
            byte[] sd = new byte[length_needed];
            if (NativeMethods.WTSGetListenerSecurity(SafeTerminalServerHandle.CurrentServer, IntPtr.Zero,
                0, Name, SecurityInformation.Dacl | SecurityInformation.Sacl, sd, sd.Length, out length_needed))
            {
                return SecurityDescriptor.Parse(sd, NtType.GetTypeByName(TerminalServicesUtils.TERMINAL_SERVER_LISTENER_NT_TYPE_NAME), throw_on_error);
            }

            if (Win32Utils.GetLastWin32Error() != Win32Error.ERROR_INSUFFICIENT_BUFFER)
            {
                return Win32Utils.CreateResultFromDosError<SecurityDescriptor>(throw_on_error);
            }
        }
        return Win32Utils.CreateResultFromDosError<SecurityDescriptor>(throw_on_error);
    }

    /// <summary>
    /// Get the security descriptor for the listener.
    /// </summary>
    /// <returns>The listener security descriptor.</returns>
    public SecurityDescriptor GetSecurityDescriptor()
    {
        return GetSecurityDescriptor(true).Result;
    }
    #endregion
}
