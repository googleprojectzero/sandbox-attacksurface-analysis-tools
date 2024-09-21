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

using NtCoreLib.Ndr.Com;
using NtCoreLib.Ndr.Dce;
using NtCoreLib.Ndr.Rpc;
using System;
using System.Collections.Generic;

#nullable enable

namespace NtCoreLib.Ndr.Formatter;

/// <summary>
/// Context for NDR formatting.
/// </summary>
internal interface INdrFormatterContext
{
    string IidToName(Guid iid);

    string GetProxyName(NdrComProxyInterface proxy);

    string SimpleTypeToName(NdrFormatCharacter format);

    string FormatPointer(string base_type);

    string FormatComment(string comment, params object[] args);

    string FormatLineComment(string comment, params object[] args);

    string FormatType(NdrBaseTypeReference base_type);

    string FormatArrayType(NdrBaseArrayTypeReference array_type);

    string FormatTypeDefs();

    void FormatProcedure(NdrStringBuilder builder, NdrProcedureDefinition procedure);

    void FormatRpcInterface(NdrStringBuilder builder, RpcServerInterface rpc_server);

    void FormatStruct(NdrStringBuilder builder, NdrBaseStructureTypeReference type);

    void FormatUnion(NdrStringBuilder builder, NdrUnionTypeReference type);

    void FormatComProxy(NdrStringBuilder builder, NdrComProxyInterface type);

    string FormatAttributes(IEnumerable<string> attributes);
}