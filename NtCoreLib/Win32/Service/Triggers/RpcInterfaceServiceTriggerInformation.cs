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

#nullable enable

using NtCoreLib.Ndr.Rpc;
using NtCoreLib.Win32.Rpc.EndpointMapper;
using NtCoreLib.Win32.Service.Interop;
using System;

namespace NtCoreLib.Win32.Service.Triggers;

/// <summary>
/// Service trigger for an RPC interface.
/// </summary>
public class RpcInterfaceServiceTriggerInformation : ServiceTriggerInformation
{
    /// <summary>
    /// The interface ID for the RPC server.
    /// </summary>
    public Guid InterfaceId { get; }

    /// <summary>
    /// The optional object UUID for the RPC server.
    /// </summary>
    public Guid? ObjUuid { get; }

    private protected override string GetSubTypeDescription()
    {
        return $"{base.GetSubTypeDescription()} {InterfaceId}{(ObjUuid.HasValue ? $":{ObjUuid}" : "")}" ;
    }

    internal RpcInterfaceServiceTriggerInformation(SERVICE_TRIGGER trigger) : base(trigger)
    {
        if (CustomData.Count > 0 && CustomData[0].DataType == ServiceTriggerDataType.String)
        {
            string[] guids = CustomData[0].Data.Split(':');
            try
            {
                if (guids.Length > 0)
                {
                    InterfaceId = Guid.Parse(guids[0]);
                }
                if (guids.Length > 1)
                {
                    ObjUuid = Guid.Parse(guids[1]);
                }
            }
            catch (FormatException)
            {
            }
        }
    }

    /// <inheritdoc/>
    public override void Trigger()
    {
        RpcStringBinding binding = new("ncalrpc")
        {
            ObjUuid = ObjUuid
        };
        RpcEndpointMapper.MapEndpoint(binding, new RpcSyntaxIdentifier(InterfaceId), false);
    }
}
