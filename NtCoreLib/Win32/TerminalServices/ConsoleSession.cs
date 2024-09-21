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

using NtCoreLib.Win32.TerminalServices.Interop;

namespace NtCoreLib.Win32.TerminalServices;

/// <summary>
/// Class to represent a console session.
/// </summary>
public sealed class ConsoleSession
{
    /// <summary>
    /// The session ID.
    /// </summary>
    public int SessionId { get; }
    /// <summary>
    /// The Session Name.
    /// </summary>
    public string SessionName { get; }
    /// <summary>
    /// The Username if any user authenticated.
    /// </summary>
    public string UserName { get; }
    /// <summary>
    /// The Domain Name for the User.
    /// </summary>
    public string DomainName { get; }
    /// <summary>
    /// The Console Session State.
    /// </summary>
    public ConsoleSessionConnectState State { get; }
    /// <summary>
    /// The hostname for the client.
    /// </summary>
    public string HostName { get; }
    /// <summary>
    /// The Farm name for Virtual Machine Farm.
    /// </summary>
    public string FarmName { get; }
    /// <summary>
    /// Get the FQ User Name.
    /// </summary>
    public string FullyQualifiedUserName => string.IsNullOrEmpty(DomainName) ? UserName : $"{DomainName}\\{UserName}";

    internal ConsoleSession(WTS_SESSION_INFO_1 info)
    {
        SessionId = info.SessionId;
        UserName = info.pUserName ?? string.Empty;
        SessionName = info.pSessionName ?? string.Empty;
        State = info.State;
        DomainName = info.pDomainName ?? string.Empty;
        HostName = info.pHostName ?? string.Empty;
        FarmName = info.pFarmName ?? string.Empty;
    }
}
