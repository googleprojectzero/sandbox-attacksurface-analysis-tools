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

using System;

namespace NtApiDotNet
{
    /// <summary>
    /// Object type entry for an access check.
    /// </summary>
    public sealed class ObjectTypeEntry
    {
        /// <summary>
        /// The object level.
        /// </summary>
        public int Level { get; set; }
        /// <summary>
        /// The object type GUID.
        /// </summary>
        public Guid ObjectType { get; set; }
        /// <summary>
        /// The name of the object.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public ObjectTypeEntry()
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="object_type">The object type GUID.</param>
        /// <param name="level">The object level.</param>
        /// <param name="name">The name of the object type entry.</param>
        public ObjectTypeEntry(Guid object_type, int level, string name)
        {
            ObjectType = object_type;
            Level = level;
            Name = name;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="object_type">The object type GUID.</param>
        /// <param name="level">The object level.</param>
        public ObjectTypeEntry(Guid object_type, int level) 
            : this(object_type, level, null)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="object_type">The object type GUID.</param>
        public ObjectTypeEntry(Guid object_type)
            : this(object_type, 0)
        {
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The object formatted.</returns>
        public override string ToString()
        {
            return $"{ObjectType} - Level {Level}";
        }

        internal ObjectTypeList ToStruct(DisposableList resources)
        {
            return new ObjectTypeList()
            {
                Level = (short)Level,
                ObjectType = resources.AddResource(new SafeStructureInOutBuffer<Guid>(ObjectType)).DangerousGetHandle()
            };
        }
    }

#pragma warning restore 1591
}
