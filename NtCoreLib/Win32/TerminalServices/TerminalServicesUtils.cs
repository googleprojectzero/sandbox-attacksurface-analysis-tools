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

using NtCoreLib.Native.SafeHandles;
using NtCoreLib.Win32.TerminalServices.Interop;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtCoreLib.Win32.TerminalServices;

/// <summary>
/// Utilities for terminal services.
/// </summary>
public static class TerminalServicesUtils
{
    #region Static Methods
    /// <summary>
    /// Get a list of all console sessions.
    /// </summary>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The list of console sessions.</returns>
    public static NtResult<IEnumerable<ConsoleSession>> GetConsoleSessions(bool throw_on_error)
    {
        return TerminalServer.Current.GetConsoleSessions(throw_on_error);
    }

    /// <summary>
    /// Get a list of all console sessions.
    /// </summary>
    /// <returns>The list of console sessions.</returns>
    public static IEnumerable<ConsoleSession> GetConsoleSessions()
    {
        return GetConsoleSessions(true).Result;
    }

    /// <summary>
    /// Get session token for a session ID.
    /// </summary>
    /// <param name="session_id">The session ID.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The session token.</returns>
    public static NtResult<NtToken> GetSessionToken(int session_id, bool throw_on_error)
    {
        return NativeMethods.WTSQueryUserToken(session_id,
            out SafeKernelObjectHandle handle).CreateWin32Result(throw_on_error, () => NtToken.FromHandle(handle));
    }

    /// <summary>
    /// Get session token for a session ID.
    /// </summary>
    /// <param name="session_id">The session ID.</param>
    /// <returns>The session token.</returns>
    public static NtToken GetSessionToken(int session_id)
    {
        return GetSessionToken(session_id, true).Result;
    }

    /// <summary>
    /// Get tokens for all logged on sessions.
    /// </summary>
    /// <remarks>Needs SeTcbPrivilege to work.</remarks>
    /// <returns>The list of session tokens.</returns>
    public static IEnumerable<NtToken> GetSessionTokens()
    {
        List<NtToken> tokens = new();
        foreach (var session in GetConsoleSessions())
        {
            if (session.State == ConsoleSessionConnectState.Active
                        && NativeMethods.WTSQueryUserToken(session.SessionId, out SafeKernelObjectHandle handle))
            {
                tokens.Add(NtToken.FromHandle(handle));
            }
        }
        
        return tokens;
    }

    /// <summary>
    /// Get the list of terminal service listeners.
    /// </summary>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The list of listener names.</returns>
    public static NtResult<IEnumerable<TerminalServerListener>> GetListeners(bool throw_on_error)
    {
        int count = 0;
        NativeMethods.WTSEnumerateListeners(SafeTerminalServerHandle.CurrentServer, IntPtr.Zero, 0, null, ref count);
        if (Win32Utils.GetLastWin32Error() != Win32Error.ERROR_INSUFFICIENT_BUFFER)
        {
            return Win32Utils.CreateResultFromDosError<IEnumerable<TerminalServerListener>>(throw_on_error);
        }

        WTSLISTENERNAME[] names = Enumerable.Range(0, count).Select(i => new WTSLISTENERNAME()).ToArray();
        return NativeMethods.WTSEnumerateListeners(SafeTerminalServerHandle.CurrentServer, IntPtr.Zero, 0,
            names, ref count).CreateWin32Result(throw_on_error, () => names.Select(n => new TerminalServerListener(n)));
    }

    /// <summary>
    /// Get the list of terminal service listeners.
    /// </summary>
    /// <returns>The list of listener names.</returns>
    public static IEnumerable<TerminalServerListener> GetListeners()
    {
        return GetListeners(true).Result;
    }
    #endregion

    #region Static Properties
    /// <summary>
    /// The fake NT type name for a terminal server listener.
    /// </summary>
    public static string TERMINAL_SERVER_LISTENER_NT_TYPE_NAME => "TSListener";
    #endregion
}
