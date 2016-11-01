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
using System.Reflection;

namespace DumpProcessMitigations
{
    class Program
    {
        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("Usage: DumpProcessMitigations [options]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
        }

        static Dictionary<string, PropertyInfo> _props = new Dictionary<string, PropertyInfo>(StringComparer.OrdinalIgnoreCase);

        static bool HasPropertySet(NtProcessMitigations mitigations, IEnumerable<string> props)
        {
            foreach (string propname in props)
            {
                if (_props.ContainsKey(propname))
                {
                    if ((bool)_props[propname].GetValue(mitigations))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        static void FormatEntry(string name, object value)
        {
            Console.WriteLine("- {0,-45}: {1}", name, value);
        }

        static string GetCommandLine(NtProcess process)
        {
            try
            {
                return process.CommandLine;
            }
            catch (NtException)
            {
                return String.Empty;
            }
        }

        static void DumpProcessEntry(NtProcess entry, HashSet<string> mitigation_filter, bool all_mitigations, bool print_command_line)
        {
            try
            {
                NtProcessMitigations mitigations = entry.Mitigations;

                Console.WriteLine("Process Mitigations: {0,8} - {1}", entry.ProcessId, entry.GetImageFilePath(false));
                if (print_command_line)
                {
                    Console.WriteLine("Command Line: {0}", GetCommandLine(entry));
                }
                IEnumerable<PropertyInfo> props = _props.Values.Where(p => mitigation_filter.Count == 0 || mitigation_filter.Contains(p.Name));
                foreach (PropertyInfo prop in props.OrderBy(p => p.Name))
                {
                    object value = prop.GetValue(mitigations);
                    if (!all_mitigations && (value is bool))
                    {
                        if (!(bool)value)
                        {
                            continue;
                        }
                    }

                    FormatEntry(prop.Name, prop.GetValue(mitigations));
                }
                Console.WriteLine();
            }
            catch (NtException)
            {
                // Can end up here if the process is exiting.
            }
        }

        static bool ContainsString(string s, HashSet<string> filter_set)
        {
            foreach (string filter in filter_set)
            {
                if (s.Contains(filter))
                    return true;
            }
            return false;
        }

        static void Main(string[] args)
        {
            bool show_help = false;
            HashSet<string> mitigation_filter = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            HashSet<string> process_filter = new HashSet<string>(StringComparer.CurrentCultureIgnoreCase);
            HashSet<int> pid_filter = new HashSet<int>();
            HashSet<string> cmdline_filter = new HashSet<string>();
            bool all_mitigations = false;
            bool print_command_line = false;
            OptionSet p = new OptionSet() {
                        { "t|type=", "A filter for processes with a specific mitigation to display",  v => mitigation_filter.Add(v.Trim()) },
                        { "f|filter=", "A filter for the path of a process to display",  v => process_filter.Add(v.Trim()) },
                        { "p|pid=", "A filter for a specific PID to display", v => pid_filter.Add(int.Parse(v)) },
                        { "c|cmd=", "A filter for the command line of a process to display",  v => cmdline_filter.Add(v.Trim().ToLower()) },
                        { "a|all", "Show all process mitigations", v => all_mitigations = v != null },
                        { "l|cmdline", "Print the command line of the process", v => print_command_line = v != null },
                        { "h|help",  "show this message and exit",
                           v => show_help = v != null },
                    };

            foreach (PropertyInfo prop in typeof(NtProcessMitigations).GetProperties())
            {
                _props.Add(prop.Name.ToLower(), prop);
            }

            try
            {
                p.Parse(args);

                if (show_help)
                {
                    ShowHelp(p);
                }
                else
                {
                    NtToken.EnableDebugPrivilege();
                    IEnumerable<NtProcess> procs = NtProcess.GetProcesses(ProcessAccessRights.QueryInformation);

                    if (cmdline_filter.Count > 0)
                    {
                        procs = procs.Where(e => ContainsString(GetCommandLine(e).ToLower(), cmdline_filter));
                    }

                    if (pid_filter.Count > 0)
                    {
                        procs = procs.Where(e => pid_filter.Contains(e.ProcessId));
                    }

                    if (process_filter.Count > 0)
                    {
                        procs = procs.Where(e => ContainsString(e.GetImageFilePath(false).ToLower(), process_filter));
                    }

                    if (mitigation_filter.Count > 0)
                    {
                        procs = procs.Where(e => HasPropertySet(e.Mitigations, mitigation_filter));
                    }

                    foreach (NtProcess entry in procs)
                    {
                        DumpProcessEntry(entry, mitigation_filter, all_mitigations, print_command_line);
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
