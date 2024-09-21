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

using Microsoft.Win32;
using NtCoreLib.Ndr.Interop;
using NtCoreLib.Ndr.Rpc;
using NtCoreLib.Win32.Rpc.Interop;
using NtCoreLib.Win32.Rpc.Transport;
using System;
using System.Collections.Concurrent;

namespace NtCoreLib.Win32.Rpc.EndpointMapper;

/// <summary>
/// Class to represent an RPC endpoint.
/// </summary>
public sealed class RpcEndpoint
{
    #region Private Members
    private readonly Lazy<RpcServerProcessInformation> _server_process_info;
    private static readonly ConcurrentDictionary<Guid, bool> _com_interface_check = CreateComDict();

    private static ConcurrentDictionary<Guid, bool> CreateComDict()
    {
        ConcurrentDictionary<Guid, bool> ret = new();
        ret.TryAdd(NdrNativeUtils.IID_IUnknown, true);
        ret.TryAdd(NdrNativeUtils.IID_IDispatch, true);
        // IOrCallback
        ret.TryAdd(new Guid("18f70770-8e64-11cf-9af1-0020af6e72f4"), true);
        // Unknown
        ret.TryAdd(new Guid("016f611a-b360-4768-8b28-6779ddfde2e0"), true);
        return ret;
    }

    private RpcServerProcessInformation GetServerProcessInformation()
    {
        using var transport = RpcClientTransportFactory.ConnectEndpoint(Binding, default, null);
        return transport.ServerProcess;
    }

    private static bool GetIsComInterface(Guid interface_id)
    {
        if (!NtObjectUtils.IsWindows)
            return false;
        using var key = Registry.ClassesRoot.OpenSubKey($@"Interface\{interface_id:B}");
        return key != null;
    }
    #endregion

    #region Public Properties
    /// <summary>
    /// The interface ID of the endpoint.
    /// </summary>
    public RpcSyntaxIdentifier InterfaceId { get; }
    /// <summary>
    /// The object UUID.
    /// </summary>
    public Guid ObjectUuid { get; }
    /// <summary>
    /// The RPC string binding.
    /// </summary>
    public RpcStringBinding Binding { get; }
    /// <summary>
    /// Optional annotation.
    /// </summary>
    public string Annotation { get; }
    /// <summary>
    /// RPC binding string.
    /// </summary>
    public string BindingString => Binding.ToString();
    /// <summary>
    /// Endpoint protocol sequence.
    /// </summary>
    public string ProtocolSequence => Binding.ProtocolSequence;
    /// <summary>
    /// Endpoint network address.
    /// </summary>
    public string NetworkAddress => Binding.NetworkAddress;
    /// <summary>
    /// Endpoint name.
    /// </summary>
    public string Endpoint => Binding.Endpoint;
    /// <summary>
    /// Endpoint network options.
    /// </summary>
    public string NetworkOptions => Binding.NetworkOptions;
    /// <summary>
    /// Indicates this endpoint is registered with the endpoint mapper.
    /// </summary>
    public bool Registered { get; }
    /// <summary>
    /// Indicates this endpoint is a COM interface.
    /// </summary>
    public bool IsComInterface => _com_interface_check.GetOrAdd(InterfaceId.Uuid, GetIsComInterface);
    /// <summary>
    /// The RPC protocol tower for information purposes if known.
    /// </summary>
    public RpcProtocolTower ProtocolTower { get; }
    #endregion

    #region Internal Members
    internal RpcEndpoint(RPC_IF_ID if_id, UUID uuid, SafeRpcStringHandle annotation, SafeRpcBindingHandle binding, bool registered)
        : this(new RpcSyntaxIdentifier(if_id), RpcStringBinding.Parse(binding.ToString()), 
              annotation: annotation?.ToString(), registered: registered)
    {
        if (ObjectUuid == Guid.Empty)
            ObjectUuid = uuid.Uuid;
    }
    #endregion

    #region Constructors
    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="interface_id">The RPC interface ID.</param>
    /// <param name="binding">The RPC string binding.</param>
    /// <param name="annotation">The RPC annotation.</param>
    /// <param name="registered">Whether the RPC interface is registered.</param>
    /// <param name="protocol_tower">Optional RPC protocol tower.</param>
    /// <exception cref="ArgumentException">Thrown if invalid parameters passed.</exception>
    public RpcEndpoint(RpcSyntaxIdentifier interface_id, RpcStringBinding binding,
        string annotation = null, bool registered = false, RpcProtocolTower protocol_tower = null)
    {
        InterfaceId = interface_id;
        Binding = binding ?? throw new ArgumentNullException(nameof(binding));
        ObjectUuid = binding.ObjUuid.GetValueOrDefault();
        Annotation = annotation ?? string.Empty;
        ProtocolTower = protocol_tower;
        Registered = registered;
        _server_process_info = new Lazy<RpcServerProcessInformation>(GetServerProcessInformation);
    }
    #endregion

    #region Public Methods
    /// <summary>
    /// Overridden ToString method.
    /// </summary>
    /// <returns>String form of the object.</returns>
    public override string ToString()
    {
        return $"[{InterfaceId}] {BindingString}";
    }

    /// <summary>
    /// Get information about the server process.
    /// </summary>
    /// <returns></returns>
    public RpcServerProcessInformation GetServerProcess()
    {
        return _server_process_info.Value;
    }
    #endregion
}
