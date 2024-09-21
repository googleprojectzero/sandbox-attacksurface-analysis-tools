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

using NtCoreLib.Ndr.Interop;
using System;

#nullable enable

namespace NtCoreLib.Ndr.Rpc;

/// <summary>
/// RPC version information.
/// </summary>
[Serializable]
public readonly struct RpcVersion : IEquatable<RpcVersion>
{
    /// <summary>
    /// Major version number.
    /// </summary>
    public readonly ushort Major;

    /// <summary>
    /// Minor version number.
    /// </summary>
    public readonly ushort Minor;

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="major">Major version number.</param>
    /// <param name="minor">Minor version number.</param>
    public RpcVersion(ushort major, ushort minor)
    {
        Major = major;
        Minor = minor;
    }

    internal RPC_VERSION ToRpcVersion() => new() { MajorVersion = Major, MinorVersion = Minor };

    /// <summary>
    /// Parse the version.
    /// </summary>
    /// <param name="input">Must be of the form X.Y.</param>
    /// <returns>The parsed version.</returns>
    /// <exception cref="FormatException">Throw if the version string is invalid.</exception>
    public static RpcVersion Parse(string input)
    {
        if (!TryParse(input, out RpcVersion ver))
        {
            throw new FormatException($"Invalid version string {input}");
        }
        return ver;
    }

    /// <summary>
    /// Try and parse the version string.
    /// </summary>
    /// <param name="input">Must be of the form X.Y.</param>
    /// <param name="ver">The parsed version.</param>
    /// <returns>True if successfully parsed the version.</returns>
    public static bool TryParse(string input, out RpcVersion ver)
    {
        ver = default;
        string[] parts = input.Split('.');
        if (parts.Length != 2)
            return false;
        if (!ushort.TryParse(parts[0], out ushort major)
            || !ushort.TryParse(parts[1], out ushort minor))
        {
            return false;
        }

        ver = new RpcVersion(major, minor);
        return true;
    }

    /// <summary>
    /// Equality method.
    /// </summary>
    /// <param name="obj">The object to compare against.</param>
    /// <returns>True if equal.</returns>
    public override bool Equals(object? obj)
    {
        return obj is RpcVersion version && Equals(version);
    }

    /// <summary>
    /// Equality method.
    /// </summary>
    /// <param name="other">The object to compare against.</param>
    /// <returns>True if equal.</returns>
    public bool Equals(RpcVersion other)
    {
        return Major == other.Major &&
               Minor == other.Minor;
    }

    /// <summary>
    /// Get hash code.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode()
    {
        int hashCode = 317314336;
        hashCode = hashCode * -1521134295 + Major.GetHashCode();
        hashCode = hashCode * -1521134295 + Minor.GetHashCode();
        return hashCode;
    }

    /// <summary>
    /// Format as a string.
    /// </summary>
    /// <returns>The version as a string.</returns>
    public override string ToString()
    {
        return $"{Major}.{Minor}";
    }

    /// <summary>
    /// Equality method.
    /// </summary>
    /// <param name="left">Left operand.</param>
    /// <param name="right">Right operand.</param>
    /// <returns>True if equal.</returns>
    public static bool operator ==(RpcVersion left, RpcVersion right) => left.Equals(right);

    /// <summary>
    /// Inequality method.
    /// </summary>
    /// <param name="left">Left operand.</param>
    /// <param name="right">Right operand.</param>
    /// <returns>True if not equal.</returns>
    public static bool operator !=(RpcVersion left, RpcVersion right) => !(left == right);
}