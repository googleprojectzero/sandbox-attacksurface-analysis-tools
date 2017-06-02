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

namespace CheckAlpcPortAccess
{
    class Program
    {
        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("Usage: CheckAlpcPortAccess [options] [pid1... pidN]");
            Console.WriteLine("This application tries to check access to ALPC ports based on their handles.");
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
                bool print_sddl = false;

                OptionSet opts = new OptionSet() {
                        { "p|pid=", "Specify a PID of a process for access check.", v => pid = int.Parse(v.Trim()) },
                        { "sddl", "Print SDDL security descriptor.", v => print_sddl = v != null },
                        { "h|help",  "show this message and exit",
                           v => show_help = v != null },
                    };

                HashSet<int> pids = new HashSet<int>(opts.Parse(args).Select(a => int.Parse(a)));
                if (show_help)
                {
                    ShowHelp(opts);
                    return;
                }

                Dictionary<string, string> ports = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

                NtToken.EnableDebugPrivilege();
                using (NtToken token = NtToken.OpenProcessToken(pid))
                {
                    IEnumerable<NtHandle> handles = NtSystemInfo.GetHandles(-1, false);
                    HashSet<ulong> checked_objects = new HashSet<ulong>();

                    if (pids.Count > 0)
                    {
                        handles = handles.Where(h => pids.Contains(h.ProcessId));
                    }

                    handles = handles.Where(h => h.ObjectType.Equals("ALPC Port", StringComparison.OrdinalIgnoreCase));
                    Dictionary<int, NtProcess> pid_to_process = new Dictionary<int, NtProcess>();
                    foreach (NtHandle handle in handles.Where(h => h.GrantedAccess.IsAccessGranted(GenericAccessRights.ReadControl)))
                    {
                        if (!pid_to_process.ContainsKey(handle.ProcessId))
                        {
                            try
                            {
                                pid_to_process[handle.ProcessId] = NtProcess.Open(handle.ProcessId, 
                                    ProcessAccessRights.QueryLimitedInformation | ProcessAccessRights.DupHandle);
                            }
                            catch (NtException)
                            {
                                pid_to_process[handle.ProcessId] = null;
                            }
                        }

                        NtProcess proc = pid_to_process[handle.ProcessId];
                        if (proc == null)
                        {
                            continue;
                        }                        

                        try
                        {
                            using (NtAlpc obj = NtAlpc.DuplicateFrom(proc, new IntPtr(handle.Handle)))
                            {
                                string name = obj.FullPath;
                                // We only care about named ALPC ports.
                                if (String.IsNullOrEmpty(name))
                                {
                                    continue;
                                }

                                if (ports.ContainsKey(name))
                                {
                                    continue;
                                }

                                SecurityDescriptor sd = obj.SecurityDescriptor;
                                AccessMask granted_access = NtSecurity.GetAllowedAccess(sd, token, AlpcAccessRights.Connect, obj.NtType.GenericMapping);
                                if (granted_access.IsEmpty)
                                {
                                    continue;
                                }
                                ports.Add(name, sd.ToSddl());
                            }
                        }
                        catch (NtException)
                        {
                        }
                    }
                }
                foreach (var pair in ports.OrderBy(p => p.Key))
                {
                    Console.WriteLine(pair.Key);
                    if (print_sddl)
                    {
                        Console.WriteLine("SDDL: {0}", pair.Value);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
            }
        }
    }
}
