//  Copyright 2022 Google LLC. All Rights Reserved.
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
using System.Collections.Generic;
using NtCoreLib.Ndr.Rpc;

namespace NtCoreLib.Win32.Rpc.EndpointMapper;

internal interface IRpcEndpointMapper
{
    IEnumerable<RpcEndpoint> LookupEndpoint(RpcStringBinding search_binding, RpcEndpointInquiryFlag inquiry_flag, RpcSyntaxIdentifier? if_id_search, 
        RpcEndPointVersionOption version, Guid? uuid_search, bool throw_on_error = true);
    RpcStringBinding MapEndpoint(RpcStringBinding search_binding, RpcSyntaxIdentifier if_id_search);
}
