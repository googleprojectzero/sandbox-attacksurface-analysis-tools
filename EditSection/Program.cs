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
using System.Windows.Forms;

namespace EditSection
{
    static class Program
    {
        static string GetName(NtSection section, NtMappedSection map)
        {
            string name = String.Empty;
            try
            {
                name = map.FullPath;
                if (string.IsNullOrEmpty(name))
                {
                    name = section.FullPath;
                }
            }
            catch (NtException)
            {
            }

            return string.IsNullOrEmpty(name) ? 
                    $"Handle {section.Handle.DangerousGetHandle()} - 0x{map.DangerousGetHandle().ToInt64():X}" : name;
        }

        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            NtToken.EnableDebugPrivilege();

            try
            {
                if (args.Length == 0)
                {
                    Application.Run(new MainForm());
                }
                else
                {
                    if (args.Length < 3)
                    {
                        var handle = new SafeKernelObjectHandle(new IntPtr(int.Parse(args[0])), true);
                        
                        using (var section = NtSection.FromHandle(handle))
                        {
                            bool read_only = args.Length > 1 ? args[1].Equals("--readonly") : !section.IsAccessGranted(SectionAccessRights.MapWrite);
                            using (var map = read_only ? section.MapRead() : section.MapReadWrite())
                            {
                                using (SectionEditorForm frm = new SectionEditorForm(map, GetName(section, map), read_only))
                                {
                                    Application.Run(frm);
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}
