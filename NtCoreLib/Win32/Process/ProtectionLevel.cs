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

namespace NtCoreLib.Win32.Process;

/// <summary>
/// Specify PPL level.
/// </summary>
public enum ProtectionLevel
{
    /// <summary>
    /// None
    /// </summary>
    None = -2,
    /// <summary>
    /// Safe level as parent.
    /// </summary>
    Same = -1,
    /// <summary>
    /// Tcb PPL
    /// </summary>
    TcbPPL = 0,
    /// <summary>
    /// Windows PP
    /// </summary>
    WindowsPP = 1,
    /// <summary>
    /// Windows PPL
    /// </summary>
    WindowsPPL = 2,
    /// <summary>
    /// Antimalware PPL
    /// </summary>
    AntimalwarePPL = 3,
    /// <summary>
    /// LSA PPL
    /// </summary>
    LsaPPL = 4,
    /// <summary>
    /// Tcb PP
    /// </summary>
    TcbPP = 5,
    /// <summary>
    /// Code Generation PPL
    /// </summary>
    CodeGenPPL = 6,
    /// <summary>
    /// Authenticode PP
    /// </summary>
    AuthenticodePP = 7,
    /// <summary>
    /// App PPL
    /// </summary>
    AppPPL = 8
}
#pragma warning restore

