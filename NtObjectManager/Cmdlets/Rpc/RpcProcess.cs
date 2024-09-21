//  Copyright 2019 Google Inc. All Rights Reserved.
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
using NtCoreLib.Security.Authorization;
using NtCoreLib.Win32.Rpc.EndpointMapper;
using NtCoreLib.Win32.Rpc.Server;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NtObjectManager.Cmdlets.Rpc;

/// <summary>
/// <para type="description">An RPC process instance.</para>
/// </summary>
public sealed class RpcProcess
{
    #region Private Members
    RpcStringBinding FixAlpcBinding(RpcStringBinding binding)
    {
        if (binding.ProtocolSequence == RpcProtocolSequence.LRPC &&
            binding.Endpoint.ToLower().StartsWith(@"\rpc control\"))
        {
            return new RpcStringBinding(binding.ProtocolSequence, binding.NetworkAddress,
                binding.Endpoint.Substring(13), binding.NetworkOptions, binding.ObjUuid);
        }
        return binding;
    }
    #endregion

    #region Public Properties
    /// <summary>
    /// The process ID.
    /// </summary>
    public int ProcessId { get; }
    /// <summary>
    /// The name of the process.
    /// </summary>
    public string ProcessName => Path.GetFileName(ImagePath);
    /// <summary>
    /// The process image path.
    /// </summary>
    public string ImagePath { get; }
    /// <summary>
    /// The parsed RPC servers.
    /// </summary>
    public IReadOnlyList<RpcServer> Servers { get; }
    /// <summary>
    /// The RPC string bindings.
    /// </summary>
    public IReadOnlyList<RpcStringBinding> Bindings { get; }
    /// <summary>
    /// The RPC interfaces exposed by this process.
    /// </summary>
    public IReadOnlyList<RpcSyntaxIdentifier> Interfaces { get; }
    /// <summary>
    /// List of binding strings.
    /// </summary>
    public IEnumerable<string> BindingStrings => Bindings.Select(b => b.ToString());
    /// <summary>
    /// List of binding strings and known security.
    /// </summary>
    public IReadOnlyDictionary<string, SecurityDescriptor> BindingSecurity { get; }
    #endregion

    #region Internal Members
    internal RpcProcess(int process_id, string image_path, 
        IEnumerable<RpcServer> servers, IEnumerable<RpcEndpoint> endpoints,
        Dictionary<RpcStringBinding, SecurityDescriptor> binding_security)
    {
        ProcessId = process_id;
        ImagePath = image_path;
        Servers = servers.ToList().AsReadOnly();
        HashSet<RpcStringBinding> bindings = new(endpoints.Select(e => FixAlpcBinding(e.Binding)));
        Bindings = bindings.ToList().AsReadOnly();
        BindingSecurity = binding_security.ToDictionary(p => FixAlpcBinding(p.Key).ToString(), p => p.Value);
        HashSet<RpcSyntaxIdentifier> interfaces = new(endpoints.Select(e => e.InterfaceId));
        Interfaces = interfaces.ToList().AsReadOnly();
    }
    #endregion
}