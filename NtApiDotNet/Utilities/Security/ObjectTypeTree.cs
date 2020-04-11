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
using System.Collections.Generic;

namespace NtApiDotNet.Utilities.Security
{
    /// <summary>
    /// A tree of Object Types.
    /// </summary>
    public sealed class ObjectTypeTree
    {
        #region Constructor
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="entries">Entries to setup in the tree.</param>
        public ObjectTypeTree(IEnumerable<ObjectTypeEntry> entries) : this()
        {
            var queue = new Queue<ObjectTypeEntry>(entries);
            BuildFromList(queue, 0);
            if (queue.Count > 0)
            {
                throw new ArgumentException("Couldn't construct tree from entries.");
            }
        }

        /// <summary>
        /// Contructor.
        /// </summary>
        public ObjectTypeTree(Guid object_type) : this()
        {
            ObjectType = object_type;
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// List of child nodes in the tree.
        /// </summary>
        public IList<ObjectTypeTree> Nodes { get; }

        /// <summary>
        /// The Object Type GUID.
        /// </summary>
        public Guid ObjectType { get; private set; }
        #endregion

        #region Public Methods
        /// <summary>
        /// Add a new object type to the tree.
        /// </summary>
        /// <param name="object_type">The object type.</param>
        /// <returns>The added tree object.</returns>
        public ObjectTypeTree AddObjectType(Guid object_type)
        {
            ObjectTypeTree ret = new ObjectTypeTree(object_type);
            Nodes.Add(ret);
            return ret;
        }
        #endregion

        /// <summary>
        /// Convert the tree to an array.
        /// </summary>
        /// <returns>The array of ObjectTypeEntry objects.</returns>
        public ObjectTypeEntry[] ToArray()
        {
            List<ObjectTypeEntry> entries = new List<ObjectTypeEntry>();
            PopulateList(entries, 0);
            return entries.ToArray();
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The object formatted.</returns>
        public override string ToString()
        {
            return $"{ObjectType} - Child Count {Nodes.Count}";
        }

        #region Private Members
        /// <summary>
        /// Contructor.
        /// </summary>
        private ObjectTypeTree()
        {
            Nodes = new List<ObjectTypeTree>();
        }

        private void PopulateList(List<ObjectTypeEntry> entries, int level)
        {
            entries.Add(new ObjectTypeEntry(ObjectType, level));
            foreach (var node in Nodes)
            {
                node.PopulateList(entries, level + 1);
            }
        }

        private void BuildFromList(Queue<ObjectTypeEntry> entries, int level)
        {
            if (entries.Count == 0)
            {
                return;
            }

            var first = entries.Dequeue();
            if (first.Level != level)
            {
                throw new ArgumentException($"Invalid Object Type level {first.Level} at level {level}");
            }

            ObjectType = first.ObjectType;
            while(entries.Count > 0)
            {
                var next = entries.Peek();
                if (next.Level <= level)
                {
                    return;
                }
               
                var entry = new ObjectTypeTree();
                entry.BuildFromList(entries, level + 1);
                Nodes.Add(entry);
            }
        }

        #endregion
    }
}
