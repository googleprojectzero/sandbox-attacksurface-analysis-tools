//  Copyright 2019 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet.Win32.RpcClient
{
    /// <summary>
    /// Flags for the RPC client builder.
    /// </summary>
    [Flags]
    public enum RpcClientBuilderFlags
    {
        /// <summary>
        /// None.
        /// </summary>
        None = 0,
        /// <summary>
        /// Generate public methods to create defined complex types.
        /// </summary>
        GenerateValueConstructors = 1,
        /// <summary>
        /// Enable debugging for built clients.
        /// </summary>
        EnableDebugging = 2,
    }

    /// <summary>
    /// Arguments for the RPC client builder.
    /// </summary>
    public struct RpcClientBuilderArguments
    {
        /// <summary>
        /// Builder flags.
        /// </summary>
        public RpcClientBuilderFlags Flags { get; set; }
        /// <summary>
        /// The namespace for the client class.
        /// </summary>
        public string NamespaceName { get; set; }
        /// <summary>
        /// The class name of the client.
        /// </summary>
        public string ClientName { get; set; }

        private Tuple<RpcClientBuilderFlags, string, string> CreateTuple()
        {
            return Tuple.Create(Flags, NamespaceName, ClientName);
        }

        /// <summary>
        /// GetHashCode implementation.
        /// </summary>
        /// <returns>The hash code.</returns>
        public override int GetHashCode()
        {
            return CreateTuple().GetHashCode();
        }

        /// <summary>
        /// Equals implementation.
        /// </summary>
        /// <param name="obj">The object to compare against.</param>
        /// <returns>True if the object is equal.</returns>
        public override bool Equals(object obj)
        {
            if (obj is RpcClientBuilderArguments left)
            {
                return CreateTuple().Equals(left.CreateTuple());
            }
            return false;
        }
    }
}
