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

namespace NtCoreLib.Win32.Rpc.Client.Builder;

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
    /// <summary>
    /// Wrap complex type decoders with a unique pointer.
    /// </summary>
    PointerComplexTypeDecoders = 0x200,
    /// <summary>
    /// Marshal pipe parameters using arrays.
    /// </summary>
    MarshalPipesAsArrays = 0x400,
    /// <summary>
    /// Generate a wrapper type for all the built types.
    /// </summary>
    GenerateWrapperType = 0x800,
    /// <summary>
    /// Generate type strict context handle types if they are used in the interface.
    /// </summary>
    GenerateTypeStrictHandles = 0x1000,
    /// <summary>
    /// Exclude generating the client.
    /// </summary>
    ExcludeClient = 0x2000,
}
