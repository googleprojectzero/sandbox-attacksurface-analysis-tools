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

using NDesk.Options;
using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CommonObjects
{
    class Program
    {
        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("Usage: CommonObjects [options] pid0 pid1 [pid2..pidN]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
        }

        static string GetObjectName(IEnumerable<NtHandle> entries)
        {
            foreach (NtHandle entry in entries)
            {
                using (NtObject obj = entry.GetObject())
                {
                    if (obj != null)
                    {
                        return obj.FullPath;
                    }
                }
            }
            return String.Empty;
        }

        static void Main(string[] args)
        {
            try
            {
                bool show_help = false;
                string typeFilter = "";
                bool show_all = false;                

                OptionSet p = new OptionSet() {
                        { "t|type=", "An object type to filter on",  v => typeFilter = v.Trim() },
                        { "a|all", "Show all handles shared by at least one process", v => show_all = v != null },                        
                        { "h|help",  "show this message and exit", 
                           v => show_help = v != null },
                    };

                List<int> pids = p.Parse(args).Select(e => int.Parse(e)).ToList();

                if (show_help || pids.Count < 2)
                {                    
                    ShowHelp(p);                    
                }
                else
                {
                    HashSet<IntPtr> sharedObjects = new HashSet<IntPtr>();
                    Dictionary<ulong, List<NtHandle>> entries = new Dictionary<ulong, List<NtHandle>>();

                    foreach (int pid in pids)
                    {                        
                        foreach(NtHandle entry in NtSystemInfo.GetHandles(pid, true))
                        {
                            if (!entries.ContainsKey(entry.Object))
                            {
                                entries[entry.Object] = new List<NtHandle>();
                            }
                            entries[entry.Object].Add(entry);
                        }
                    }

                    int limit = show_all ? 2 : pids.Count;

                    var output = entries.Where(x => x.Value.GroupBy(y => y.ProcessId).Count() >= limit);

                    foreach (KeyValuePair<ulong, List<NtHandle>> pair in output)
                    {
                        if (String.IsNullOrWhiteSpace(typeFilter) || pair.Value[0].ObjectType.Equals(typeFilter, StringComparison.OrdinalIgnoreCase))
                        {
                            Console.WriteLine("{0:X} {1} {2}", pair.Key, pair.Value[0].ObjectType, GetObjectName(pair.Value));

                            foreach (NtHandle entry in pair.Value)
                            {
                                Console.WriteLine("\t{0}/0x{0:X} {1}/0x{1:X} 0x{2:X08}",
                                    entry.ProcessId, entry.Handle, entry.GrantedAccess);
                            }
                        }
                    }
                }                
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }

        }
    }
}
