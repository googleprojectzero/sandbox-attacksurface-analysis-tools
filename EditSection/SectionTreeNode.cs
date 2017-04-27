//  Copyright 2015 Google Inc. All Rights Reserved.
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

using NtApiDotNet;
using System;
using System.Text;
using System.Windows.Forms;

namespace EditSection
{
    class SectionTreeNode : TreeNode
    {
        private NtHandle _ent;

        private static string FormatText(NtHandle ent)
        {
            string size = String.Empty;
            try
            {
                using (NtSection section = NtSection.DuplicateFrom(ent.ProcessId, new IntPtr(ent.Handle), SectionAccessRights.Query))
                {
                    size = section.Size.ToString();
                }
            }
            catch (NtException)
            {
                size = "Unknown";
            }

            StringBuilder builder = new StringBuilder();
            NtType section_type = NtType.GetTypeByName("section");

            if (section_type.HasReadPermission(ent.GrantedAccess))
            {
                builder.Append("R");
            }

            if (section_type.HasWritePermission(ent.GrantedAccess))
            {
                builder.Append("W");
            }

            return String.Format("[{0}/0x{0:X}] {1} Size: {2} Access: {3}", ent.Handle, ent.Name, size, builder.ToString());
        }

        public SectionTreeNode(NtHandle ent)
            : base(FormatText(ent))
        {
            _ent = ent;
        }

        public NtMappedSection OpenMappedFile(bool writable)
        {
            SectionAccessRights accessRights = SectionAccessRights.MapRead;

            if (writable)
            {
                accessRights |= SectionAccessRights.MapWrite;
            }

            using (NtSection section = NtSection.DuplicateFrom(_ent.ProcessId, new IntPtr(_ent.Handle), accessRights))
            {
                return section.Map(writable ? MemoryAllocationProtect.ReadWrite : MemoryAllocationProtect.ReadOnly);
            }
        }

        public NtHandle SectionHandle { get { return _ent; } }
    }
}
