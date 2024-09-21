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

using NtCoreLib.Ndr.Rpc;
using System;
using System.Collections.Generic;
using System.IO;

namespace NtCoreLib.Win32.Rpc.Transport.PDU;

internal enum PresentationResultType
{
    Acceptance = 0,
    UserRejection,
    ProviderRejection,
    NegotiateAck
}

internal enum PresentationResultReason
{
    ReasonNotSpecified,
    AbstractSyntaxNotSupported,
    ProposedTransferSyntaxesNotSupported,
    LocalLimitExceeded
}

internal sealed class ContextResult
{
    public PresentationResultType Result { get; }
    public PresentationResultReason Reason { get; }
    public BindTimeFeatureNegotiation BindTimeFeature { get; }
    public RpcSyntaxIdentifier TransferSyntax { get; }

    private ContextResult(PresentationResultType result, int reason, RpcSyntaxIdentifier transfer_syntax)
    {
        Result = result;
        if (result == PresentationResultType.NegotiateAck)
        {
            BindTimeFeature = (BindTimeFeatureNegotiation)reason;
        }
        else
        {
            Reason = (PresentationResultReason)reason;
        }
        TransferSyntax = transfer_syntax;
    }

    public static List<ContextResult> ReadList(BinaryReader reader)
    {
        int count = reader.ReadByte();
        reader.ReadAllBytes(3);

        List<ContextResult> ret = new();

        for (int i = 0; i < count; ++i)
        {
            PresentationResultType result = (PresentationResultType)reader.ReadUInt16();
            int reason = reader.ReadUInt16();
            Guid transfer_syntax_id = new(reader.ReadAllBytes(16));
            ushort major_version = reader.ReadUInt16();
            ushort minor_version = reader.ReadUInt16();
            ret.Add(new ContextResult(result, reason, new RpcSyntaxIdentifier(transfer_syntax_id, major_version, minor_version)));
        }

        return ret;
    }
}
