//  Copyright 2015 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using HandleUtils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace EditSection
{
    class ProcessTreeNode : TreeNode
    {
        private int _id;
        private string _name;

        public ProcessTreeNode(Process p) 
            : base(String.Format("[{0}/0x{0:X}] {1}", p.Id, p.ProcessName))
        {
            _id = p.Id;
            _name = p.ProcessName;
            Nodes.Add(new TreeNode("Dummy"));
        }

        public void PopulateChildren()
        {
            Nodes.Clear();
            List<HandleEntry> handles = NativeBridge.GetHandlesForPid(_id);
            foreach (HandleEntry h in handles)
            {
                if (h.TypeName.Equals("section", StringComparison.OrdinalIgnoreCase))
                {
                    Nodes.Add(new SectionTreeNode(h));
                }
            }            
        }
    }
}
