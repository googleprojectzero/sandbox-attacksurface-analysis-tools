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

namespace NtApiDotNet.Utilities.ASN1.Builder
{
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
        /// <exception cref="ArgumentException">Thrown if less than 2 components.</exception>
        public DERObjectIdentifier(string oid)
        {
            ObjectIdentifier = oid.Split('.').Select(i => int.Parse(i)).ToList().AsReadOnly();
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The object identifier as a string.</returns>
        public override string ToString()
        {
            return string.Join(".", ObjectIdentifier);
        }

        void IDERObject.Write(DERBuilder builder)
        {
            builder.WriteObjectId(ObjectIdentifier);
        }
    }
}
