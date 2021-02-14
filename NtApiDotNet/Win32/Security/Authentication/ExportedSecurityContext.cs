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

using System;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Class to represent an exported security context.
    /// </summary>
    public sealed class ExportedSecurityContext : IDisposable
    {
        private readonly bool _client;

        /// <summary>
        /// The name of the package for this security context.
        /// </summary>
        public string Package { get; }
        /// <summary>
        /// The serialized context.
        /// </summary>
        public byte[] SerializedContext { get; }
        /// <summary>
        /// The context's token.
        /// </summary>
        public NtToken Token { get; }

        internal ExportedSecurityContext(string package, byte[] context, NtToken token, bool client)
        {
            Package = package;
            SerializedContext = context;
            Token = token;
            _client = client;
        }

        /// <summary>
        /// Dispose the exported context.
        /// </summary>
        public void Dispose()
        {
            ((IDisposable)Token).Dispose();
        }
    }
}
