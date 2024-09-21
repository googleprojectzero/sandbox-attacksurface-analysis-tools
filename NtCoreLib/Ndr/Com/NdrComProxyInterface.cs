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

// NOTE: This file is a modified version of COMProxyInstance.cs from OleViewDotNet
// https://github.com/tyranid/oleviewdotnet. It's been relicensed from GPLv3 by
// the original author James Forshaw to be used under the Apache License for this
// project.

using System;
using System.Collections.Generic;
using System.Linq;
using NtCoreLib.Ndr.Dce;
using NtCoreLib.Ndr.Interop;
using NtCoreLib.Ndr.Rpc;

namespace NtCoreLib.Ndr.Com;

/// <summary>
/// Class to represent a single COM proxy definition.
/// </summary>
[Serializable]
public sealed class NdrComProxyInterface
{
    /// <summary>
    /// The name of the proxy interface.
    /// </summary>
    public string Name { get; set; }
    /// <summary>
    /// The IID of the proxy interface.
    /// </summary>
    public Guid Iid { get; }
    /// <summary>
    /// The base IID of the proxy interface.
    /// </summary>
    public Guid BaseIid { get; }
    /// <summary>
    /// Get the list of syntax info,
    /// </summary>
    public IReadOnlyList<MidlSyntaxInfo> SyntaxInfo { get; }
    /// <summary>
    /// The number of dispatch methods on the interface.
    /// </summary>
    public int DispatchCount { get; }
    /// <summary>
    /// List of parsed procedures for the interface.
    /// </summary>
    public IReadOnlyList<NdrProcedureDefinition> Procedures => SyntaxInfo.OfType<MidlSyntaxInfoDce>().FirstOrDefault()?.Procedures ?? Array.Empty<NdrProcedureDefinition>();

    internal NdrComProxyInterface(string name, Guid iid, Guid base_iid, int dispatch_count, IEnumerable<MidlSyntaxInfo> syntax_info)
    {
        Name = name;
        Iid = iid;
        BaseIid = base_iid == Guid.Empty ? NdrNativeUtils.IID_IUnknown : base_iid;
        DispatchCount = dispatch_count;
        SyntaxInfo = syntax_info.ToList().AsReadOnly();
    }

    /// <summary>
    /// Creates a proxy definition from a list of procedures.
    /// </summary>
    /// <param name="name">The name of the proxy interface.</param>
    /// <param name="iid">The IID of the proxy interface.</param>
    /// <param name="base_iid">The base IID of the proxy interface.</param>
    /// <param name="dispatch_count">The total dispatch count for the proxy interface.</param>
    /// <param name="procedures">The list of parsed procedures for the proxy interface.</param>
    /// <returns></returns>
    public static NdrComProxyInterface FromProcedures(string name, Guid iid, Guid base_iid, int dispatch_count, IEnumerable<NdrProcedureDefinition> procedures)
    {
        List<MidlSyntaxInfo> syntax_info = new()
        {
            new MidlSyntaxInfoDce(procedures, new NdrTypeCache())
        };
        return new NdrComProxyInterface(name, iid, base_iid, dispatch_count, syntax_info);
    }
}
