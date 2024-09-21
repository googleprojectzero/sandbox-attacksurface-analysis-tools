//  Copyright 2016 Google Inc. All Rights Reserved.
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

namespace NtCoreLib.Win32.Security.Authentication.Logon;

/// <summary>
/// Logon type
/// </summary>
public enum SecurityLogonType
{
    /// <summary>
    /// This is used to specify an undefined logon type
    /// </summary>
    UndefinedLogonType = 0,
    /// <summary>
    /// Interactively logged on (locally or remotely)
    /// </summary>
    Interactive = 2,
    /// <summary>
    /// Accessing system via network
    /// </summary>
    Network,
    /// <summary>
    /// Started via a batch queue
    /// </summary>
    Batch,
    /// <summary>
    /// Service started by service controller
    /// </summary>
    Service,
    /// <summary>
    /// Proxy logon
    /// </summary>
    Proxy,
    /// <summary>
    /// Unlock workstation
    /// </summary>
    Unlock,
    /// <summary>
    /// Network logon with cleartext credentials
    /// </summary>
    NetworkCleartext,
    /// <summary>
    /// Clone caller, new default credentials
    /// </summary>
    NewCredentials,
    /// <summary>
    /// Remove interactive.
    /// </summary>
    RemoteInteractive,
    /// <summary>
    /// Cached Interactive.
    /// </summary>
    CachedInteractive,
    /// <summary>
    /// Cached Remote Interactive.
    /// </summary>
    CachedRemoteInteractive,
    /// <summary>
    /// Cached unlock.
    /// </summary>
    CachedUnlock
}
