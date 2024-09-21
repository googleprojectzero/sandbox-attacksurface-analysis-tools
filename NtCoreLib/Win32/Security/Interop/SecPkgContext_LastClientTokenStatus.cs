//  Copyright 2021 Google Inc. All Rights Reserved.
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

using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Security.Interop;

/// <summary>
/// Indicates the last client token status for the client context.
/// </summary>
public enum SecPkgLastClientTokenStatus
{
    /// <summary>
    /// Yes it's the last token.
    /// </summary>
    Yes,
    /// <summary>
    /// No it's not the last token.
    /// </summary>
    No,
    /// <summary>
    /// It might be, who knows?
    /// </summary>
    Maybe
}

[StructLayout(LayoutKind.Sequential)]
internal struct SecPkgContext_LastClientTokenStatus
{
    public SecPkgLastClientTokenStatus LastClientTokenStatus;
}
