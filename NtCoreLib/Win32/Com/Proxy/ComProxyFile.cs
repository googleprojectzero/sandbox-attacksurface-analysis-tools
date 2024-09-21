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
using Microsoft.Win32;
using NtCoreLib.Ndr.Com;
using NtCoreLib.Ndr.Formatter;
using NtCoreLib.Ndr.Interop;
using NtCoreLib.Ndr.Parser;

namespace NtCoreLib.Win32.Com.Proxy;

/// <summary>
/// Class to represent a COM proxy file.
/// </summary>
public sealed class ComProxyFile
{
    #region Private Members
    private Lazy<Dictionary<Guid, ComProxyInterface>> _interfaces;

    private static string ReadRegistryStringValue(string key_name, string value_name)
    {
        using var key = Registry.ClassesRoot.OpenSubKey(key_name);
        if (key == null)
            return null;
        return key.GetValue(value_name) as string;
    }

    private Dictionary<Guid, string> GetIidDict()
    {
        Dictionary<Guid, string> dict = new()
        {
            [NdrNativeUtils.IID_IUnknown] = "IUnknown",
            [NdrNativeUtils.IID_IDispatch] = "IDispatch",
            [NdrNativeUtils.IID_IInspectable] = "IInspectable"
        };
        foreach (var intf in Proxies.SelectMany(p => p.Interfaces))
        {
            if (string.IsNullOrWhiteSpace(intf.Name))
                continue;
            dict[intf.Iid] = ComUtils.DemangleWinRTName(intf.Name);
        }
        return dict;
    }

    private Dictionary<Guid, ComProxyInterface> GetInterfaces()
    {
        return Proxies.SelectMany(p => p.Interfaces)
            .Select(p => new ComProxyInterface(p)).ToDictionary(p => p.InterfaceId);
    }

    private ComProxyFile(string path, IEnumerable<NdrComProxy> proxies)
    {
        Path = path;
        Proxies = proxies.ToList().AsReadOnly();
        _interfaces = new(GetInterfaces);
    }
    #endregion

    #region Public Properties
    /// <summary>
    /// Path to the COM proxy file.
    /// </summary>
    public string Path { get; }

    /// <summary>
    /// The CLSID of the proxy instance if known.
    /// </summary>
    public Guid Clsid { get; }

    /// <summary>
    /// List of COM proxies.
    /// </summary>
    public IReadOnlyList<NdrComProxy> Proxies { get; }

    /// <summary>
    /// Get list of COM proxy interfaces.
    /// </summary>
    public IReadOnlyList<ComProxyInterface> Interfaces => _interfaces.Value.Values.ToList().AsReadOnly();
    #endregion

    #region Public Methods
    /// <summary>
    /// Format the COM proxy file as text.
    /// </summary>
    /// <param name="flags">Flags for the formatter..</param>
    /// <param name="format">Output text format type.</param>
    /// <returns>The formatted RPC server.</returns>
    public string FormatAsText(NdrFormatterFlags flags = 0, NdrFormatterTextFormat format = NdrFormatterTextFormat.Idl)
    {
        NdrFormatter formatter = NdrFormatter.Create(format, GetIidDict(), ComUtils.DemangleWinRTName, flags);
        formatter.HeaderText.Add($"Path: {Path}");
        if (Clsid != Guid.Empty)
        {
            formatter.HeaderText.Add($"Clsid: {Clsid}");
        }

        formatter.ComProxies.AddRange(Proxies.SelectMany(p => p.Interfaces));
        formatter.ComplexTypes.AddRange(Proxies.SelectMany(p => p.ComplexTypes));
        return formatter.Format();
    }

    /// <summary>
    /// Get the proxy interface for an IID.
    /// </summary>
    /// <param name="iid">The interface ID.</param>
    /// <returns>The COM proxy interface.</returns>
    public ComProxyInterface GetInterface(Guid iid)
    {
        return _interfaces.Value[iid];
    }
    #endregion

    #region Static Methods
    /// <summary>
    /// Read a COM proxy file from 
    /// </summary>
    /// <param name="path">The path to the COM proxy DLL file.</param>
    /// <param name="clsid">The proxy instance CLSID. Needed if the DLL doesn't export GetProxyDllInfo.</param>
    /// <returns>The parsed COM proxy file.</returns>
    public static ComProxyFile FromFile(string path, Guid clsid = default)
    {
        return new(path, new NdrParser().ReadFromComProxyFile(path, clsid));
    }

    /// <summary>
    /// Read COM proxy information from a CLSID.
    /// </summary>
    /// <param name="clsid">The CLSID for the COM proxy implementation.</param>
    /// <returns>The parsed COM proxy definition.</returns>
    public static ComProxyFile FromClsid(Guid clsid)
    {
        string com_proxy_file = ReadRegistryStringValue($@"CLSID\{clsid:B}\InProcServer32", null) ?? throw new ArgumentException("No proxy DLL for interface.");
        return FromFile(com_proxy_file, clsid);
    }

    /// <summary>
    /// Read COM proxy information from an IID.
    /// </summary>
    /// <param name="iid">The IID to read the proxy file for.</param>
    /// <returns>The parsed COM proxy definition.</returns>
    public static ComProxyFile FromIid(Guid iid)
    {
        string proxy_clsid = ReadRegistryStringValue($@"Interface\{iid:B}\ProxyStubClsid32", null) ?? throw new ArgumentException("No proxy information for interface.");
        if (!Guid.TryParse(proxy_clsid, out Guid clsid))
        {
            throw new ArgumentException("Invalid proxy clsid GUID.");
        }
        return FromClsid(clsid);
    }
    #endregion
}
