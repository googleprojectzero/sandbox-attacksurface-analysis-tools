//  Copyright 2021 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet.Win32.DirectoryService
{
    /// <summary>
    /// Structure to represent an attribute for a class.
    /// </summary>
    public struct DirectoryServiceSchemaClassAttribute
    {
        /// <summary>
        /// The name of the attribute.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// True if the attribute is required.
        /// </summary>
        public bool Required { get; }

        /// <summary>
        /// True if the attribute can only be modified by system.
        /// </summary>
        public bool System { get; }

        internal DirectoryServiceSchemaClassAttribute(string name, bool required, bool system)
        {
            Name = name;
            Required = required;
            System = system;
        }

        /// <summary>
        /// Get the hash code for the attribute.
        /// </summary>
        /// <returns>The hash code.</returns>
        public override int GetHashCode()
        {
            return Tuple.Create(Name, Required, System).GetHashCode();
        }

        /// <summary>
        /// Check attributes for equality.
        /// </summary>
        /// <param name="obj">The other attribute to check.</param>
        /// <returns>True if equal.</returns>
        public override bool Equals(object obj)
        {
            return Tuple.Create(Name, Required, System).Equals(obj);
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The name of the attribute.</returns>
        public override string ToString()
        {
            return Name;
        }
    }
}
