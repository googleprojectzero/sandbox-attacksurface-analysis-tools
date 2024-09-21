//  Copyright 2018 Google Inc. All Rights Reserved.
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

#nullable enable


using System;

namespace NtCoreLib.Ndr.Rpc;

/// <summary>
/// Base syntax information.
/// </summary>
[Serializable]
public abstract class MidlSyntaxInfo
{
    /// <summary>
    /// The RPC transfer syntax.
    /// </summary>
    public RpcSyntaxIdentifier TransferSyntax { get; }

    private protected MidlSyntaxInfo(RpcSyntaxIdentifier transfer_syntax)
    {
        TransferSyntax = transfer_syntax;
    }
}
