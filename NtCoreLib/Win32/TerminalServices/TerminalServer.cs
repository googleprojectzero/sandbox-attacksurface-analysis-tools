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

using NtCoreLib.Utilities.Memory;
using NtCoreLib.Win32.TerminalServices.Interop;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtCoreLib.Win32.TerminalServices;

/// <summary>
/// A class to access the information on a terminal server.
/// </summary>
public sealed class TerminalServer
{
    #region Private Members
    private readonly SafeTerminalServerHandle _handle;

    private TerminalServer(string server_name, SafeTerminalServerHandle handle)
    {
        ServerName = server_name;
        _handle = handle;
    }

    #endregion

    #region Public Members
    /// <summary>
    /// The opened name of the server.
    /// </summary>
    public string ServerName { get; }
    #endregion

    #region Static Methods
    /// <summary>
    /// Open a connection to a terminal server.
    /// </summary>
    /// <param name="server_name">The hostname of the terminal server. If you pass null it'll open the virtualization host on the local machine.</param>
    /// <param name="throw_on_error"></param>
    /// <returns>The terminal server connection.</returns>
    public static NtResult<TerminalServer> Open(string? server_name, bool throw_on_error)
    {
        return NativeMethods.WTSOpenServerExW(server_name)
            .CreateWin32Result(throw_on_error, h => new TerminalServer(server_name ?? "VirtualizationHost", h));
    }

    /// <summary>
    /// Open a connection to a terminal server.
    /// </summary>
    /// <param name="server_name">The hostname of the terminal server.</param>
    /// <returns>The terminal server connection.</returns>
    public static TerminalServer Open(string? server_name)
    {
        return Open(server_name, true).Result;
    }
    #endregion

    #region Static Properties
    /// <summary>
    /// Open the current local terminal server.
    /// </summary>
    public static TerminalServer Current => new("Current", SafeTerminalServerHandle.CurrentServer);
    #endregion

    #region Public Methods
    /// <summary>
    /// Get a list of all console sessions.
    /// </summary>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The list of console sessions.</returns>
    public NtResult<IEnumerable<ConsoleSession>> GetConsoleSessions(bool throw_on_error)
    {
        List<ConsoleSession> sessions = new();
        IntPtr session_info = IntPtr.Zero;
        int session_count = 0;
        try
        {
            int level = 1;
            if (!NativeMethods.WTSEnumerateSessionsEx(_handle,
                ref level, 0, out session_info, out session_count))
            {
                return Win32Utils.CreateResultFromDosError<IEnumerable<ConsoleSession>>(throw_on_error);
            }

            sessions.AddRange(session_info.ReadArray<WTS_SESSION_INFO_1>(session_count).Select(w => new ConsoleSession(w)));
        }
        finally
        {
            if (session_info != IntPtr.Zero)
            {
                NativeMethods.WTSFreeMemoryEx(WTS_TYPE_CLASS.WTSTypeSessionInfoLevel1,
                    session_info, session_count);
            }
        }

        return sessions.AsReadOnly().CreateResult<IEnumerable<ConsoleSession>>();
    }

    /// <summary>
    /// Get a list of all console sessions.
    /// </summary>
    /// <returns>The list of console sessions.</returns>
    public IEnumerable<ConsoleSession> GetConsoleSessions()
    {
        return GetConsoleSessions(true).Result;
    }
    #endregion
}
