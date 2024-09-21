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

using NtCoreLib.Ndr.Interop;
using NtCoreLib.Win32.Rpc.EndpointMapper;
using NtCoreLib.Win32.Rpc.Interop;
using System;
using System.Collections.Generic;

namespace NtCoreLib.Ndr.Rpc;

/// <summary>
/// Structure to present an RPC syntax identifier.
/// </summary>
[Serializable]
public readonly struct RpcSyntaxIdentifier : IEquatable<RpcSyntaxIdentifier>
{
    /// <summary>
    /// The syntax UUID.
    /// </summary>
    public Guid Uuid { get; }

    /// <summary>
    /// The syntax version.
    /// </summary>
    public RpcVersion Version { get; }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="uuid">The syntax UUID.</param>
    /// <param name="version">The syntax version.</param>
    public RpcSyntaxIdentifier(Guid uuid, RpcVersion version = default)
    {
        Uuid = uuid;
        Version = version;
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="uuid">The syntax UUID.</param>
    /// <param name="major">The major version number.</param>
    /// <param name="minor">The minor version number.</param>
    public RpcSyntaxIdentifier(Guid uuid, ushort major, ushort minor) 
        : this(uuid, new RpcVersion(major, minor))
    {
    }

    internal RpcSyntaxIdentifier(RPC_IF_ID if_id)
        : this(if_id.Uuid, new RpcVersion(if_id.VersMajor, if_id.VersMinor))
    {
    }

    internal RpcSyntaxIdentifier(RPC_SYNTAX_IDENTIFIER syntax_id) 
        : this(syntax_id.SyntaxGUID, syntax_id.SyntaxVersion.MajorVersion, syntax_id.SyntaxVersion.MinorVersion)
    {
    }

    /// <summary>
    /// The interface ID for the DCE NDR transfer syntax.
    /// </summary>
    public static RpcSyntaxIdentifier DCETransferSyntax => new(NdrNativeUtils.DCE_TransferSyntax, new RpcVersion(2, 0));

    /// <summary>
    /// The interface ID for the DCE NDR transfer syntax.
    /// </summary>
    public static RpcSyntaxIdentifier NDR64TransferSyntax => new(NdrNativeUtils.NDR64_TransferSyntax, new RpcVersion(1, 0));

    /// <summary>
    /// Overridden ToString method.
    /// </summary>
    /// <returns>The syntax ID as a string.</returns>
    public override string ToString()
    {
        return $"{Uuid}:{Version}";
    }

    internal RPC_IF_ID_EPT ToRpcIfId()
    {
        return new RPC_IF_ID_EPT()
        {
            Uuid = Uuid,
            VersMajor = Version.Major,
            VersMinor = Version.Minor
        };
    }

    internal RPC_SYNTAX_IDENTIFIER ToSyntaxIdentifier()
    {
        return new RPC_SYNTAX_IDENTIFIER(Uuid, Version.Major, Version.Minor);
    }

    /// <summary>
    /// Equality method.
    /// </summary>
    /// <param name="obj">The object to compare to.</param>
    /// <returns>True if equal.</returns>
    public override bool Equals(object obj)
    {
        if (obj is not RpcSyntaxIdentifier)
            return false;
        return Equals((RpcSyntaxIdentifier)obj);
    }

    /// <summary>
    /// Equality method.
    /// </summary>
    /// <param name="other">The object to compare to.</param>
    /// <returns>True if equal.</returns>
    public bool Equals(RpcSyntaxIdentifier other)
    {
        return Uuid.Equals(other.Uuid) &&
               Version.Equals(other.Version);
    }

    /// <summary>
    /// Get hashcode.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode()
    {
        int hashCode = -637891239;
        hashCode = hashCode * -1521134295 + Uuid.GetHashCode();
        hashCode = hashCode * -1521134295 + Version.GetHashCode();
        return hashCode;
    }

    /// <summary>
    /// Equality operator.
    /// </summary>
    /// <param name="left">The left object.</param>
    /// <param name="right">The right object.</param>
    /// <returns>True if equal.</returns>
    public static bool operator ==(RpcSyntaxIdentifier left, RpcSyntaxIdentifier right)
    {
        return EqualityComparer<RpcSyntaxIdentifier>.Default.Equals(left, right);
    }

    /// <summary>
    /// Inequality operator.
    /// </summary>
    /// <param name="left">The left object.</param>
    /// <param name="right">The right object.</param>
    /// <returns>True if not equal.</returns>
    public static bool operator !=(RpcSyntaxIdentifier left, RpcSyntaxIdentifier right)
    {
        return !(left == right);
    }
}
