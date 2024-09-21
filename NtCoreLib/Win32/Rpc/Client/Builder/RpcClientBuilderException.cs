﻿//  Copyright 2023 Google LLC. All Rights Reserved.
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
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.Linq;

namespace NtCoreLib.Win32.Rpc.Client.Builder;

/// <summary>
/// Exception thrown if an RPC client builder fails.
/// </summary>
public sealed class RpcClientBuilderException : Exception
{
    /// <summary>
    /// The list of compiler errors if there are any.
    /// </summary>
    public IReadOnlyList<CompilerError> Errors { get; }

    internal RpcClientBuilderException(string message, CompilerErrorCollection errors) : base(message)
    {
        Errors = (errors.Cast<CompilerError>() ?? Array.Empty<CompilerError>()).ToList().AsReadOnly();
    }
}
