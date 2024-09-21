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
using System.Linq;

#nullable enable

namespace NtCoreLib.Ndr.Formatter;

/// <summary>
/// A class which describes a text formatter for NDR data.
/// </summary>
/// <remarks>Note, the formatter can maintain state, call reset if you want to reuse the formatter.</remarks>
public sealed class NdrFormatter
{
    #region Private Members
    private readonly Func<INdrFormatterContext> _create_context;

    private NdrFormatter(Func<INdrFormatterContext> create_context)
    {
        _create_context = create_context;
    }

    private static void FormatComplexType(INdrFormatterContext context, NdrStringBuilder builder, NdrComplexTypeReference complex_type)
    {
        if (complex_type is NdrBaseStructureTypeReference struct_type)
        {
            context.FormatStruct(builder, struct_type);
        }
        else if (complex_type is NdrUnionTypeReference union_type)
        {
            context.FormatUnion(builder, union_type);
        }
        else
        {
            builder.AppendLine(context.FormatComment("Unknown Complex Type {0}", complex_type.Name));
        }
        builder.AppendLine();
    }
    #endregion

    #region Public Methods
    /// <summary>
    /// Format a complex type using the current formatter.
    /// </summary>
    /// <param name="complex_type">The complex type to format.</param>
    /// <returns>The formatted complex type.</returns>
    /// <remarks>This is just for informational use. You should use the Format procedure instead.</remarks>
    public string FormatComplexType(NdrComplexTypeReference complex_type)
    {
        NdrStringBuilder builder = new();
        FormatComplexType(_create_context(), builder, complex_type);
        return builder.ToString();
    }

    /// <summary>
    /// Format a procedure using the current formatter.
    /// </summary>
    /// <param name="procedure">The procedure to format.</param>
    /// <returns>The formatted procedure.</returns>
    /// <remarks>This is just for informational use. You should use the Format procedure instead.</remarks>
    public string FormatProcedure(NdrProcedureDefinition procedure)
    {
        NdrStringBuilder builder = new();
        _create_context().FormatProcedure(builder, procedure);
        return builder.ToString();
    }

    /// <summary>
    /// Format a COM proxy using the current formatter.
    /// </summary>
    /// <param name="com_proxy">The COM proxy to format.</param>
    /// <returns>The formatted COM proxy.</returns>
    /// <remarks>This is just for informational use. You should use the Format procedure instead.</remarks>
    public string FormatComProxy(NdrComProxyInterface com_proxy)
    {
        NdrStringBuilder builder = new();
        _create_context().FormatComProxy(builder, com_proxy);
        return builder.ToString();
    }

    /// <summary>
    /// Format an RPC server interface using the current formatter.
    /// </summary>
    /// <param name="rpc_server">The RPC server.</param>
    /// <returns>The formatted RPC server interface.</returns>
    /// <remarks>This is just for informational use. You should use the Format procedure instead.</remarks>
    public string FormatRpcServerInterface(RpcServerInterface rpc_server)
    {
        NdrStringBuilder builder = new();
        _create_context().FormatRpcInterface(builder, rpc_server);
        return builder.ToString();
    }

    /// <summary>
    /// Reset the formatter back to its default state.
    /// </summary>
    public void Reset()
    {
        HeaderText.Clear();
        ComplexTypes.Clear();
        RpcServers.Clear();
        ComProxies.Clear();
    }

    /// <summary>
    /// Format the NDR based on the current state.
    /// </summary>
    /// <returns></returns>
    public string Format()
    {
        NdrStringBuilder builder = new();
        INdrFormatterContext context = _create_context();
        foreach (NdrComplexTypeReference complex_type in ComplexTypes)
        {
            FormatComplexType(context, builder, complex_type);
        }

        foreach (RpcServerInterface rpc_server in RpcServers)
        {
            context.FormatRpcInterface(builder, rpc_server);
        }

        foreach (NdrComProxyInterface com_proxy in ComProxies)
        {
            context.FormatComProxy(builder, com_proxy);
        }

        NdrStringBuilder ret_builder = new();
        var headers = HeaderText.Select(l => context.FormatLineComment(l)).Where(l => l.Length > 0);
        if (headers.Any())
        {
            foreach (var line in headers)
            {
                ret_builder.AppendLine(line);
            }
            ret_builder.AppendLine();
        }

        string typedefs = context.FormatTypeDefs();
        if (typedefs.Length > 0)
        {
            ret_builder.AppendLine(typedefs).AppendLine();
        }
        ret_builder.AppendLine(builder.ToString());
        return ret_builder.ToString();
    }
    #endregion

    #region Public Properties
    /// <summary>
    /// Text for the headers.
    /// </summary>
    public List<string> HeaderText { get; } = new();
    /// <summary>
    /// List of complex types.
    /// </summary>
    public List<NdrComplexTypeReference> ComplexTypes { get; } = new();
    /// <summary>
    /// List of RPC servers.
    /// </summary>
    public List<RpcServerInterface> RpcServers { get; } = new();
    /// <summary>
    /// List of COM proxies.
    /// </summary>
    public List<NdrComProxyInterface> ComProxies { get; } = new();
    #endregion

    #region Static Methods
    /// <summary>
    /// Create an NDR formatter.
    /// </summary>
    /// <param name="format">The output text format.</param>
    /// <param name="iids_to_names">Specify a dictionary of IIDs to names.</param>
    /// <param name="demangle_com_name">Function to demangle COM interface names during formatting.</param>
    /// <param name="flags">Flags for the formatter.</param>
    /// <returns>The default formatter.</returns>
    public static NdrFormatter Create(NdrFormatterTextFormat format = NdrFormatterTextFormat.Idl,
        IDictionary<Guid, string>? iids_to_names = null, Func<string, string>? demangle_com_name = null, NdrFormatterFlags flags = NdrFormatterFlags.None)
    {
        Func<INdrFormatterContext> create_context = format switch
        {
            NdrFormatterTextFormat.Idl => () => new IdlNdrFormatterContext(iids_to_names, demangle_com_name, flags),
            NdrFormatterTextFormat.CSharp => () => new DefaultNdrFormatterContext(iids_to_names, demangle_com_name, flags, false),
            NdrFormatterTextFormat.Cpp => () => new DefaultNdrFormatterContext(iids_to_names, demangle_com_name, flags, true),
            _ => throw new ArgumentException("Invalid text format type", nameof(format)),
        };
        return new NdrFormatter(create_context);
    }
    #endregion
}
