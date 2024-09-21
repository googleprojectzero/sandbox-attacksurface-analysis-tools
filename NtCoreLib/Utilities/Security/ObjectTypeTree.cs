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
using System.Linq;

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
            BuildFromList(null, queue, 0);
            if (queue.Count > 0)
            {
                throw new ArgumentException("Couldn't construct tree from entries.");
            }
        }

        /// <summary>
        /// Contructor.
        /// </summary>
        /// <param name="object_type">The object type GUID.</param>
        /// <param name="name">The name of the root object.</param>
        public ObjectTypeTree(Guid object_type, string name) : this()
        {
            ObjectType = object_type;
            Name = name;
        }

        /// <summary>
        /// Contructor.
        /// </summary>
        /// <param name="object_type">The object type GUID.</param>
        public ObjectTypeTree(Guid object_type) : this(object_type, null)
        {
        }

        /// <summary>
        /// Contructor.
        /// </summary>
        /// <param name="object_type">The object type GUID as a string.</param>
        public ObjectTypeTree(string object_type) 
            : this(Guid.Parse(object_type))
        {
        }

        #endregion

        #region Public Properties
        /// <summary>
        /// List of child nodes in the tree.
        /// </summary>
        public IReadOnlyList<ObjectTypeTree> Nodes => _nodes.AsReadOnly();

        /// <summary>
        /// The parent of this tree.
        /// </summary>
        public ObjectTypeTree Parent { get; private set; }

        /// <summary>
        /// The Object Type GUID.
        /// </summary>
        public Guid ObjectType { get; private set; }

        /// <summary>
        /// Optional access mask for use in access checking.
        /// </summary>
        public AccessMask RemainingAccess { get; set; }

        /// <summary>
        /// Optional label for this tree entry.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Indicates the number of total entries this tree contains.
        /// </summary>
        public int Count => 1 + _nodes.Sum(n => n.Count);

        #endregion

        #region Public Methods

        /// <summary>
        /// Add a new object type to the tree.
        /// </summary>
        /// <param name="object_type">The object type.</param>
        /// <param name="name">The name of the node.</param>
        /// <returns>The added tree object.</returns>
        public ObjectTypeTree AddNode(Guid object_type, string name)
        {
            ObjectTypeTree ret = new ObjectTypeTree(object_type, name);
            AddNode(ret);
            return ret;
        }

        /// <summary>
        /// Add a new object type to the tree.
        /// </summary>
        /// <param name="object_type">The object type.</param>
        /// <returns>The added tree object.</returns>
        public ObjectTypeTree AddNode(Guid object_type)
        {
            return AddNode(object_type, null);
        }

        /// <summary>
        /// Add an existing node to the tree.
        /// </summary>
        /// <param name="node">The node to add.</param>
        public void AddNode(ObjectTypeTree node)
        {
            node.Parent = this;
            _nodes.Add(node);
        }

        /// <summary>
        /// Add an existing list of nodes to the tree.
        /// </summary>
        /// <param name="nodes">The nodes to add.</param>
        public void AddNodeRange(IEnumerable<ObjectTypeTree> nodes)
        {
            foreach (var node in nodes)
            {
                AddNode(node);
            }
        }

        /// <summary>
        /// Removes all object types from the tree.
        /// </summary>
        /// <param name="object_type">The object type.</param>
        /// <returns>The removed tree object.</returns>
        public void RemoveAllNodes(Guid object_type)
        {
            _nodes.RemoveAll(t => t.ObjectType == object_type);
        }

        /// <summary>
        /// Removes all object types from the tree.
        /// </summary>
        /// <param name="object_type">The object type.</param>
        /// <returns>The removed tree object.</returns>
        public void RemoveNode(ObjectTypeTree object_type)
        {
            _nodes.Remove(object_type);
        }

        /// <summary>
        /// Remove the current tree entry from the parent.
        /// </summary>
        public void Remove()
        {
            if (Parent == null)
                return;
            Parent._nodes.Remove(this);
        }

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
        /// Clone the object type tree.
        /// </summary>
        /// <returns>The cloned tree.</returns>
        public ObjectTypeTree Clone()
        {
            return new ObjectTypeTree(ToArray());
        }

        /// <summary>
        /// Set the access mask of this tree node and all children.
        /// </summary>
        /// <param name="mask">The mask to set.</param>
        public void SetRemainingAccess(AccessMask mask)
        {
            RemainingAccess = mask;
            foreach (var node in _nodes)
            {
                node.SetRemainingAccess(mask);
            }
        }

        /// <summary>
        /// Remove access mask from this tree node and children and propgate that up the tree.
        /// </summary>
        /// <param name="mask">The mask to remove.</param>
        public void RemoveRemainingAccess(AccessMask mask)
        {
            RemainingAccess &= ~mask;
            foreach (var node in _nodes)
            {
                node.RemoveRemainingAccess(mask);
            }

            var current = this;
            while (current.Parent != null)
            {
                current.Parent.RemainingAccess |= current.RemainingAccess;
                current = current.Parent;
            }
        }

        /// <summary>
        /// Find an object type tree entry based on a GUID.
        /// </summary>
        /// <param name="object_type">The object type GUID.</param>
        /// <returns>The first entry found, null if doesn't exist.</returns>
        public ObjectTypeTree Find(Guid object_type)
        {
            if (ObjectType == object_type)
                return this;

            foreach (var node in _nodes)
            {
                var ret = node.Find(object_type);
                if (ret != null)
                    return ret;
            }

            return null;
        }

        /// <summary>
        /// Split the tree up to reduce the maximum number of entries.
        /// </summary>
        /// <remarks>This will try and keep whole branches together if at all possible, 
        /// but might split them up. This could result in incorrect access checking.</remarks>
        /// <param name="max_entry">The maximum number of entries per tree.</param>
        /// <returns>One or more split trees.</returns>
        public IEnumerable<ObjectTypeTree> Split(int max_entry)
        {
            if (max_entry < 1)
                throw new ArgumentException("Max entry can't be less than 1", nameof(max_entry));
            if (Count < max_entry)
                return new[] { this };

            List<ObjectTypeTree> ret = new List<ObjectTypeTree>();
            ObjectTypeTree new_tree = new ObjectTypeTree(ObjectType, Name);
            ret.Add(new_tree);
            int remaining = max_entry - 1;

            foreach (var node in Nodes.SelectMany(n => n.Split(max_entry - 1)).OrderBy(n => n.Count))
            {
                int count = node.Count;
                if (count > remaining)
                {
                    new_tree = new ObjectTypeTree(ObjectType, Name);
                    remaining = max_entry - 1;
                    ret.Add(new_tree);
                }
                new_tree.AddNode(node.Clone());
                remaining -= count;
            }
            return ret.ToArray();
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The object formatted.</returns>
        public override string ToString()
        {
            return $"{ObjectType} - Child Count {Nodes.Count}";
        }
        #endregion

        #region Private Members

        private readonly List<ObjectTypeTree> _nodes;

        private ObjectTypeTree()
        {
            _nodes = new List<ObjectTypeTree>();
        }

        private void PopulateList(List<ObjectTypeEntry> entries, int level)
        {
            entries.Add(new ObjectTypeEntry(ObjectType, level) { Name = Name ?? string.Empty });
            foreach (var node in Nodes)
            {
                node.PopulateList(entries, level + 1);
            }
        }

        private void BuildFromList(ObjectTypeTree parent, Queue<ObjectTypeEntry> entries, int level)
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
            Name = first.Name ?? string.Empty;
            Parent = parent;
            while(entries.Count > 0)
            {
                var next = entries.Peek();
                if (next.Level <= level)
                {
                    return;
                }
               
                var entry = new ObjectTypeTree();
                entry.BuildFromList(this, entries, level + 1);
                _nodes.Add(entry);
            }
        }

        #endregion
    }
}
