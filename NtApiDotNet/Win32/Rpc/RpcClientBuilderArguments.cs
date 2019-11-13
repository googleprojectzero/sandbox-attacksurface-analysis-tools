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

namespace NtApiDotNet.Win32.Rpc
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
        /// Generate public properties on the client to create defined complex types.
        /// </summary>
        /// <remarks>If not specified then constructors will be defined on the types themselves.</remarks>
        GenerateConstructorProperties = 1,
        /// <summary>
        /// Insert breakpoints into the start of every generated method. Also enables debugging.
        /// </summary>
        InsertBreakpoints = 2,
        /// <summary>
        /// Disable calculated correlation information. This will prevent automatic updating of array and 
        /// string lengths based on other parameters or fields. This might result in unexpected behavior or
        /// call failures. This won't disable correlations for union types or constant correlations.
        /// </summary>
        DisableCalculatedCorrelations = 4,
        /// <summary>
        /// Don't emit any namespace, normally not specifying a namespace will auto-generate one.
        /// </summary>
        NoNamespace = 8,
        /// <summary>
        /// Output FC_CHAR as if the original compiler had specified unsigned char types. Basically converts
        /// System.SByte to System.Byte where needed which makes the methods easier to use.
        /// </summary>
        UnsignedChar = 0x10,
        /// <summary>
        /// Return ref/out parameters via a structure rather than requiring ref/out parameters in client
        /// methods.
        /// </summary>
        StructureReturn = 0x20,
        /// <summary>
        /// When using StructureReturn hide the original out/ref methods.
        /// </summary>
        HideWrappedMethods = 0x40,
        /// <summary>
        /// Generate encode/decode methods for complex types.
        /// </summary>
        GenerateComplexTypeEncodeMethods = 0x80,
        /// <summary>
        /// Exclude any text in the source code which can change between generations.
        /// </summary>
        ExcludeVariableSourceText = 0x100,
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
        /// <summary>
        /// The class name of the complex type encoding class.
        /// </summary>
        public string EncoderName { get; set; }
        /// <summary>
        /// The class name of the complex type decoder class.
        /// </summary>
        public string DecoderName { get; set; }
        /// <summary>
        /// Enable debugging on built code.
        /// </summary>
        public bool EnableDebugging { get; set; }

        private Tuple<RpcClientBuilderFlags, string, string, string, string, bool> CreateTuple()
        {
            return Tuple.Create(Flags, NamespaceName, ClientName, 
                EncoderName, DecoderName, EnableDebugging);
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
