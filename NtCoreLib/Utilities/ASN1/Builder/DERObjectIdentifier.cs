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
using System.Linq;

namespace NtCoreLib.Utilities.ASN1.Builder;

/// <summary>
/// An object identifier DER object.
/// </summary>
public sealed class DERObjectIdentifier : IDERObject
{
    /// <summary>
    /// The object identifier as a list of integers.
    /// </summary>
    public IReadOnlyList<int> ObjectIdentifier { get; }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="oid">The list of object identifier components.</param>
    /// <exception cref="ArgumentException">Thrown if less than 2 components.</exception>
    public DERObjectIdentifier(IEnumerable<int> oid)
    {
        if (oid is null)
        {
            throw new ArgumentNullException(nameof(oid));
        }

        ObjectIdentifier = oid.ToList().AsReadOnly();
        if (ObjectIdentifier.Count < 2)
            throw new ArgumentException("Invalid OID, needs at least two components.", nameof(oid));
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="oid">The object identifier as a string.</param>
    /// <exception cref="ArgumentException">Thrown if less than 2 components or invalid.</exception>
    public DERObjectIdentifier(string oid) : this(Parse(oid).ObjectIdentifier)
    {
    }

    /// <summary>
    /// Overridden ToString method.
    /// </summary>
    /// <returns>The object identifier as a string.</returns>
    public override string ToString()
    {
        return string.Join(".", ObjectIdentifier);
    }

    /// <summary>
    /// Try and parse a string to an OID.
    /// </summary>
    /// <param name="value">The OID as a string.</param>
    /// <param name="oid">The parsed OID.</param>
    /// <returns>Returns true if successful.</returns>
    public static bool TryParse(string value, out DERObjectIdentifier oid)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"'{nameof(value)}' cannot be null or whitespace.", nameof(value));
        }

        oid = null;
        List<int> values = new();
        foreach (var part in value.Split('.'))
        {
            if (!int.TryParse(part, out int v))
                return false;
            values.Add(v);
        }
        oid = new DERObjectIdentifier(values);
        return true;
    }

    /// <summary>
    /// Parse a string to an OID.
    /// </summary>
    /// <param name="value">The string to parse.</param>
    /// <returns>The parsed OID.</returns>
    /// <exception cref="ArgumentException">Thrown if the string is invalid.</exception>
    public static DERObjectIdentifier Parse(string value)
    {
        if (!TryParse(value, out DERObjectIdentifier oid))
            throw new ArgumentException("Value is not a valid OID.", nameof(value));
        return oid;
    }

    void IDERObject.Write(DERBuilder builder)
    {
        builder.WriteObjectId(ObjectIdentifier);
    }
}
