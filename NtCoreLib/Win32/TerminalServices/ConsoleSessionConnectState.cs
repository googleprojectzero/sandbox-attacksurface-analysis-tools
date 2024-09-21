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

namespace NtCoreLib.Win32.TerminalServices;

/// <summary>
/// State of the console session.
/// </summary>
public enum ConsoleSessionConnectState
{
    /// <summary>
    /// User logged on to WinStation
    /// </summary>
    Active,
    /// <summary>
    /// WinStation connected to client
    /// </summary>
    Connected,
    /// <summary>
    /// In the process of connecting to client
    /// </summary>
    ConnectQuery,
    /// <summary>
    /// Shadowing another WinStation
    /// </summary>
    Shadow,
    /// <summary>
    /// WinStation logged on without client
    /// </summary>
    Disconnected,
    /// <summary>
    /// Waiting for client to connect
    /// </summary>
    Idle,
    /// <summary>
    /// WinStation is listening for connection
    /// </summary>
    Listen,
    /// <summary>
    /// WinStation is being reset
    /// </summary>
    Reset,
    /// <summary>
    /// WinStation is down due to error
    /// </summary>
    Down,
    /// <summary>
    /// WinStation in initialization
    /// </summary>
    Init,
}
