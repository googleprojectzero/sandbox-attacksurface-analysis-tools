//  Copyright 2020 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet
{
    /// <summary>
    /// Flags representing what generic access the entry maps to.
    /// </summary>
    [Flags]
    public enum GenericAccessType
    {
        /// <summary>
        /// Not mapped to any access.
        /// </summary>
        None = 0,
        /// <summary>
        /// Mapped to read.
        /// </summary>
        Read = 1,
        /// <summary>
        /// Mapped to write.
        /// </summary>
        Write = 2,
        /// <summary>
        /// Mapped to execute.
        /// </summary>
        Execute = 4,
        /// <summary>
        /// Mapped to All.
        /// </summary>
        All = 8
    }

    /// <summary>
    /// A structure to hold an access mask to enum mapping.
    /// </summary>
    public struct AccessMaskEntry
    {
        /// <summary>
        /// The access mask.
        /// </summary>
        public AccessMask Mask { get; }
        /// <summary>
        /// The value of the access mask entry enumeration.
        /// </summary>
        public Enum Value { get; }
        /// <summary>
        /// The generic access this maps to.
        /// </summary>
        public GenericAccessType GenericAccess { get; }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The string form of the entry.</returns>
        public override string ToString()
        {
            return $"{Mask:X08} - {Value}";
        }

        internal AccessMaskEntry(AccessMask mask, Enum value, GenericAccessType generic_access)
        {
            Mask = mask;
            Value = value;
            GenericAccess = generic_access;
        }
    }
}
