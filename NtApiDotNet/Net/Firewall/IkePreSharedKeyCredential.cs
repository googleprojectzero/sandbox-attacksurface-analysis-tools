//  Copyright 2021 Google LLC. All Rights Reserved.
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

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Class to represent an IKE pre-shared key credential.
    /// </summary>
    public sealed class IkePreSharedKeyCredential : IkeCredential
    {
        /// <summary>
        /// The pre-shared key.
        /// </summary>
        public byte[] Key { get; }

        /// <summary>
        /// Key flags.
        /// </summary>
        public IkeextPreSharedKeyFlags Flags { get; }

        internal IkePreSharedKeyCredential(IKEEXT_CREDENTIAL1 creds) 
            : base(creds)
        {
            var key = (IKEEXT_PRESHARED_KEY_AUTHENTICATION1)Marshal.PtrToStructure(creds.cred, 
                                                typeof(IKEEXT_PRESHARED_KEY_AUTHENTICATION1));
            Key = key.presharedKey.ToArray();
            Flags = key.flags;
        }
    }
}
