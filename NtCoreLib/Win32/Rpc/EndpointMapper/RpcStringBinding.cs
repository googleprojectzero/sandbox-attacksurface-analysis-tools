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

using NtCoreLib.Win32.Rpc.Interop;
using System;
using System.Collections.Generic;
using System.Text;

namespace NtCoreLib.Win32.Rpc.EndpointMapper;

/// <summary>
/// Class to represent an RPC binding string.
/// </summary>
public sealed class RpcStringBinding : IEquatable<RpcStringBinding>
{
    /// <summary>
    /// The object UUID.
    /// </summary>
    public Guid? ObjUuid { get; set; }
    /// <summary>
    /// The RPC protocol sequence.
    /// </summary>
    public string ProtocolSequence { get; }
    /// <summary>
    /// The RPC network address.
    /// </summary>
    public string NetworkAddress { get; set; }
    /// <summary>
    /// The RPC endpoint.
    /// </summary>
    public string Endpoint { get; set; }
    /// <summary>
    /// The RPC endpoint network options.
    /// </summary>
    public string NetworkOptions { get; set; }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="obj_uuid">The object UUID.</param>
    /// <param name="protseq">The protocol sequence.</param>
    /// <param name="network_addr">The network address.</param>
    /// <param name="endpoint">The endpoint.</param>
    /// <param name="network_options">The options.</param>
    public RpcStringBinding(string protseq, string network_addr = null,
        string endpoint = null, string network_options = null, Guid? obj_uuid = null)
    {
        if (string.IsNullOrWhiteSpace(protseq))
        {
            throw new ArgumentException($"'{nameof(protseq)}' cannot be null or whitespace.", nameof(protseq));
        }

        ProtocolSequence = protseq;
        NetworkAddress = network_addr ?? string.Empty;
        Endpoint = endpoint ?? string.Empty;
        NetworkOptions = network_options ?? string.Empty;
        ObjUuid = obj_uuid;
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="obj_uuid">The object UUID.</param>
    /// <param name="protseq">The protocol sequence.</param>
    /// <param name="network_addr">The network address.</param>
    /// <param name="endpoint">The endpoint.</param>
    /// <param name="network_options">The options.</param>
    public RpcStringBinding(string protseq, string network_addr,
        string endpoint, string network_options, string obj_uuid)
        : this(protseq, network_addr, endpoint, network_options, ParseGuid(obj_uuid))
    {
    }

    /// <summary>
    /// Converts the binding string to a string.
    /// </summary>
    /// <returns>The binding string as a string.</returns>
    public override string ToString()
    {
        StringBuilder builder = new();
        if (ObjUuid.HasValue)
        {
            builder.AppendFormat("{0}@", ObjUuid.Value);
        }
        AppendEscapedString(builder, ProtocolSequence);
        builder.Append(':');
        if (!string.IsNullOrWhiteSpace(NetworkAddress))
        {
            AppendEscapedString(builder, NetworkAddress);
        }
        if (!string.IsNullOrWhiteSpace(Endpoint) || !string.IsNullOrWhiteSpace(NetworkOptions))
        {
            builder.Append('[');
            if (!string.IsNullOrWhiteSpace(Endpoint))
            {
                AppendEscapedString(builder, Endpoint);
            }
            if (!string.IsNullOrWhiteSpace(NetworkOptions))
            {
                builder.Append(',');
                AppendEscapedString(builder, NetworkOptions);
            }
            builder.Append(']');
        }
        return builder.ToString();
    }

    /// <summary>
    /// Check if the RPC runtime supports this binding string.
    /// </summary>
    /// <exception cref="NtException">Thrown if the binding string isn't valid.</exception>
    public void Validate()
    {
        if (NtObjectUtils.IsWindows)
        {
            using (SafeRpcBindingHandle.Create(ToString()))
            {
            }
        }
    }

    /// <summary>
    /// Compose a string binding.
    /// </summary>
    /// <param name="obj_uuid">The object UUID.</param>
    /// <param name="protseq">The protocol sequence.</param>
    /// <param name="network_addr">The network address.</param>
    /// <param name="endpoint">The endpoint.</param>
    /// <param name="network_options">The options.</param>
    /// <returns>The string binding.</returns>
    public static string Compose(string protseq, string network_addr = null,
        string endpoint = null, string network_options = null, Guid? obj_uuid = null)
    {
        return new RpcStringBinding(protseq, network_addr, endpoint, network_options, obj_uuid).ToString();
    }

    /// <summary>
    /// Try and parse a RPC string binding.
    /// </summary>
    /// <param name="str">The string binding to parse.</param>
    /// <param name="binding">The parsed binding.</param>
    /// <returns>True if the parse was successful.</returns>
    public static bool TryParse(string str, out RpcStringBinding binding)
    {
        return TryParseInternal(str, out binding) == string.Empty;
    }

    /// <summary>
    /// Parse a RPC string binding.
    /// </summary>
    /// <param name="str">The string binding to parse.</param>
    /// <returns>True if the parse was successful.</returns>
    public static RpcStringBinding Parse(string str)
    {
        string error = TryParseInternal(str, out RpcStringBinding binding);
        if (error != string.Empty)
            throw new FormatException(error);
        return binding;
    }

    private static string TryParseInternal(string str, out RpcStringBinding binding)
    {
        Guid? objuuid = null;
        binding = null;

        if (ParseNext(ref str, out string uuid, '@'))
        {
            if (Guid.TryParse(uuid, out Guid g))
            {
                objuuid = g;
            }
            else
            {
                return "Invalid object UUID string.";
            }
        }

        if (!ParseNext(ref str, out string protseq, ':'))
        {
            return "Missing protocol sequence.";
        }

        if (string.IsNullOrWhiteSpace(protseq))
        {
            return "Empty protocol sequence.";
        }

        string endpoint = null;
        string networkoptions = null;

        if (ParseNext(ref str, out string networkaddr, '['))
        {
            if (!ParseNext(ref str, out string endpoint_and_options, ']'))
            {
                return "Missing closing bracket for endpoint.";
            }

            if (ParseNext(ref endpoint_and_options, out endpoint, ','))
            {
                networkoptions = endpoint_and_options;
            }
            else
            {
                endpoint = endpoint_and_options;
            }
        }
        else
        {
            if (str.Length > 0)
            {
                networkaddr = str;
                str = string.Empty;
            }
        }

        // We can ignore any trailing data as that's what the Windows APIs do.

        binding = new RpcStringBinding(UnescapeString(protseq), UnescapeString(networkaddr),
            UnescapeString(endpoint), UnescapeString(networkoptions), objuuid);
        return string.Empty;
    }

    internal NtResult<SafeRpcBindingHandle> ToHandle(bool throw_on_error)
    {
        return SafeRpcBindingHandle.Create(ToString(), throw_on_error);
    }

    private static void AppendEscapedString(StringBuilder builder, string str)
    {
        const string ESCAPED_CHARS = ",:@[\\]";

        if (str.LastIndexOfAny(ESCAPED_CHARS.ToCharArray()) < 0)
        {
            builder.Append(str);
        }
        else
        {
            foreach (char c in str)
            {
                if (ESCAPED_CHARS.IndexOf(c) >= 0)
                {
                    builder.Append('\\');
                }
                builder.Append(c);
            }
        }
    }

    private static string UnescapeString(string str)
    {
        if (str == null)
            return str;
        if (!str.Contains("\\"))
            return str;
        StringBuilder builder = new();
        for (int i = 0; i < str.Length; ++i)
        {
            if (str[i] == '\\')
            {
                if (i == str.Length - 1)
                {
                    throw new FormatException("Invalid trailing escape character.");
                }
                i++;
            }
            builder.Append(str[i]);
        }
        return builder.ToString();
    }

    private static bool ParseNext(ref string str, out string next, char c)
    {
        next = null;
        for (int i = 0; i < str.Length; ++i)
        {
            if (str[i] == '\\')
            {
                i++;
            }
            else if (str[i] == c)
            {
                next = str.Substring(0, i);
                str = str.Substring(i + 1);
                return true;
            }
        }
        return false;
    }

    private static Guid? ParseGuid(string guid)
    {
        if (guid == null)
            return null;
        return Guid.Parse(guid);
    }

    /// <inheritdoc/>
    public override bool Equals(object obj)
    {
        return Equals(obj as RpcStringBinding);
    }

    /// <inheritdoc/>
    public bool Equals(RpcStringBinding other)
    {
        return other is not null &&
               EqualityComparer<Guid?>.Default.Equals(ObjUuid, other.ObjUuid) &&
               ProtocolSequence?.ToLower() == other.ProtocolSequence?.ToLower() &&
               NetworkAddress?.ToLower() == other.NetworkAddress?.ToLower() &&
               Endpoint?.ToLower() == other.Endpoint?.ToLower() &&
               NetworkOptions?.ToLower() == other.NetworkOptions?.ToLower();
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        int hashCode = 1756919969;
        hashCode = hashCode * -1521134295 + ObjUuid.GetHashCode();
        hashCode = hashCode * -1521134295 + EqualityComparer<string>.Default.GetHashCode(ProtocolSequence?.ToLower());
        hashCode = hashCode * -1521134295 + EqualityComparer<string>.Default.GetHashCode(NetworkAddress?.ToLower());
        hashCode = hashCode * -1521134295 + EqualityComparer<string>.Default.GetHashCode(Endpoint?.ToLower());
        hashCode = hashCode * -1521134295 + EqualityComparer<string>.Default.GetHashCode(NetworkOptions?.ToLower());
        return hashCode;
    }

    /// <inheritdoc/>
    public static bool operator ==(RpcStringBinding left, RpcStringBinding right)
    {
        return EqualityComparer<RpcStringBinding>.Default.Equals(left, right);
    }

    /// <inheritdoc/>
    public static bool operator !=(RpcStringBinding left, RpcStringBinding right)
    {
        return !(left == right);
    }
}
