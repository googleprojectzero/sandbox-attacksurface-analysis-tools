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
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace EditSection
{
    class SectionTreeNode : TreeNode
    {
        private HandleEntry _ent;

        private static string FormatText(HandleEntry ent)
        {
            NativeHandle h = NativeBridge.DuplicateHandleFromProcess(ent.ProcessId, ent.Handle, 0, DuplicateHandleOptions.DuplicateSameAccess);

            try
            {
                StringBuilder builder = new StringBuilder();

                if ((ent.GrantedAccess & (int)HandleUtils.AccessRights.SectionMapRead) != 0)
                {
                    builder.Append("R");
                }

                if ((ent.GrantedAccess & (int)HandleUtils.AccessRights.SectionMapWrite) != 0)
                {
                    builder.Append("W");
                }

                return String.Format("[{0}/0x{0:X}] {1} Size: {2} Access: {3}", ent.Handle.ToInt64(), ent.ObjectName, NativeBridge.GetSectionSize(h), builder.ToString());
            }
            finally
            {
                h.Close();
            }
        }

        public SectionTreeNode(HandleEntry ent)
            : base(FormatText(ent))
        {
            _ent = ent;
        }

        public NativeMappedFile OpenMappedFile(bool writable)
        {
            AccessRights accessRights = AccessRights.SectionMapRead;

            if (writable)
            {
                accessRights |= AccessRights.SectionMapWrite;
            }

            using (NativeHandle h = NativeBridge.DuplicateHandleFromProcess(_ent.ProcessId, 
                _ent.Handle, (uint)accessRights, DuplicateHandleOptions.None))
            {
                return NativeBridge.MapFile(h, writable);
            }
        }

        public HandleEntry SectionHandle { get { return _ent; } }
    }
}
