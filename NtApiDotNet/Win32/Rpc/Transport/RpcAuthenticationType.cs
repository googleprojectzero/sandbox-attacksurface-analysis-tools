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

namespace NtApiDotNet.Win32.Rpc.Transport
{
    /// <summary>
    /// RPC authentication type.
    /// </summary>
    public enum RpcAuthenticationType
    {
        /// <summary>
        /// No authentication.
        /// </summary>
        None = 0,

        /// <summary>
        /// WinNT authentication, i.e. NTLM.
        /// </summary>
        WinNT = 10,
    }
}
