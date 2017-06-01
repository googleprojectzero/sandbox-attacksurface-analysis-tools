//  Copyright 2017 Google Inc. All Rights Reserved.
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

using NDesk.Options;
using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CheckHandleAccess
{
    class Program
    {
        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("Usage: CheckHandleAccess [options] [pid1... pidN]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
        }

        static void Main(string[] args)
        {
            try
            {
                int pid = NtProcess.Current.ProcessId;
                bool show_help = false;
                bool show_write_only = false;
                bool show_named = false;
                HashSet<string> type_filter = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                OptionSet opts = new OptionSet() {
                        { "t|type=", "Add a type filter to the handles", v => type_filter.Add(v.Trim()) },
                        { "p|pid=", "Specify a PID of a process for access check.", v => pid = int.Parse(v.Trim()) },
                        { "w", "Show only write permissions granted", v => show_write_only = v != null },
                        { "n", "Show only named handles", v => show_named = v != null },
                        { "h|help",  "show this message and exit",
                           v => show_help = v != null },
                    };

                HashSet<int> pids = new HashSet<int>(opts.Parse(args).Select(a => int.Parse(a)));
                if (show_help)
                {
                    ShowHelp(opts);
                    return;
                }

                NtToken.EnableDebugPrivilege();
                using (NtToken token = NtToken.OpenProcessToken(pid))
                {
                    IEnumerable<NtHandle> handles = NtSystemInfo.GetHandles();
                    HashSet<ulong> checked_objects = new HashSet<ulong>();

                    if (pids.Count > 0)
                    {
                        handles = handles.Where(h => pids.Contains(h.ProcessId));
                    }

                    if (type_filter.Count > 0)
                    {
                        handles = handles.Where(h => type_filter.Contains(h.ObjectType));
                    }

                    if (show_named)
                    {
                        handles = handles.Where(h => !String.IsNullOrEmpty(h.Name));
                    }

                    foreach (NtHandle handle in handles)
                    {
                        if (checked_objects.Contains(handle.Object))
                        {
                            continue;
                        }

                        SecurityDescriptor sd = handle.SecurityDescriptor;
                        if (sd == null)
                        {
                            continue;
                        }

                        NtType type = handle.NtType;
                        if (type == null)
                        {
                            continue;
                        }

                        GenericAccessRights max_access = NtSecurity.GetMaximumAccess(sd, token, type.GenericMapping);
                        if (max_access == GenericAccessRights.None)
                        {
                            continue;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }
}
