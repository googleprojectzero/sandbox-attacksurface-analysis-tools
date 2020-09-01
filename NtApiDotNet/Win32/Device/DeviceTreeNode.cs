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

using System.Collections.Generic;

namespace NtApiDotNet.Win32.Device
{
    /// <summary>
    /// Class to represent a node in a device tree.
    /// </summary>
    public sealed class DeviceTreeNode : DeviceNode
    {
        private readonly List<DeviceTreeNode> _children;
        private readonly DeviceNode _parent;

        /// <summary>
        /// List of child nodes.
        /// </summary>
        public IReadOnlyList<DeviceTreeNode> Children => _children.AsReadOnly();

        /// <summary>
        /// Indicates if the node has any children.
        /// </summary>
        public bool HasChildren => _children.Count > 0;

        /// <summary>
        /// Get the parent device node.
        /// </summary>
        /// <returns>The parent device node. Returns null if reached the root.</returns>
        public override DeviceNode Parent => _parent ?? base.Parent;

        internal void AddRange(IEnumerable<DeviceTreeNode> node)
        {
            _children.AddRange(node);
        }

        internal DeviceTreeNode(int devinst, DeviceNode parent) : base(devinst)
        {
            _children = new List<DeviceTreeNode>();
            _parent = parent;
        }
    }
}
