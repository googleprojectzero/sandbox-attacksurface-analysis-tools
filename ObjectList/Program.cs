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

using SandboxAnalysisUtils;
using NDesk.Options;
using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;

namespace ObjectList
{
    class Program
    {
        enum OutputFormat
        {
            None,
            NameOnly,
            TypeGroup,
        }

        static bool show_help = false;
        static bool recursive = false;
        static bool print_link = false;
        static bool print_sddl = false;
        static OutputFormat format;
        static HashSet<string> typeFilter = new HashSet<string>();

        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("Usage: ObjectList [options] path1 [path2..pathN]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
        }

        static void OutputNone(ObjectDirectory base_dir, IEnumerable<ObjectDirectoryEntry> objs)
        {
            if (print_sddl)
            {
                Console.WriteLine("SDDL: {0} -> {1}", base_dir.FullPath, base_dir.StringSecurityDescriptor);
            }

            foreach (ObjectDirectoryEntry ent in objs.Where(e => e.IsDirectory))
            {
                Console.WriteLine("<DIR> {0}", ent.FullPath);
            }

            foreach (ObjectDirectoryEntry ent in objs.Where(e => !e.IsDirectory))
            {
                if (ent.IsSymlink && print_link)
                {
                    Console.WriteLine("      {0} -> {1}", ent.FullPath, GetSymlinkTarget(ent));
                }
                else
                {
                    Console.WriteLine("      {0} ({1})", ent.FullPath, ent.TypeName);
                }
            }
        }

        static string GetSymlinkTarget(ObjectDirectoryEntry entry)
        {
            try
            {
                return ObjectNamespace.ReadSymlink(entry.FullPath);
            }
            catch (NtException)
            {
                return "";
            }
        }

        static void OutputTypeGroup(IEnumerable<ObjectDirectoryEntry> entries)
        {
            IEnumerable<IGrouping<string, ObjectDirectoryEntry>> groups = entries.GroupBy(e => e.TypeName, StringComparer.OrdinalIgnoreCase);

            foreach (IGrouping<string, ObjectDirectoryEntry> group in groups)
            {
                Console.WriteLine("Type: {0} (Total: {1})", group.Key, group.Count());
                foreach (ObjectDirectoryEntry entry in group)
                {
                    if (entry.IsSymlink && print_link)
                    {
                        Console.WriteLine("{0} -> {1}", entry.FullPath, GetSymlinkTarget(entry));
                    }
                    else
                    {
                        Console.WriteLine(entry.FullPath);
                    }
                }
                Console.WriteLine();
            }
        }

        static void OutputNameOnly(ObjectDirectory base_dir, IEnumerable<ObjectDirectoryEntry> entries)
        {
            foreach (ObjectDirectoryEntry entry in entries)
            {
                if (entry.IsSymlink && print_link)
                {
                    Console.WriteLine("{0} -> {1}", entry.FullPath, GetSymlinkTarget(entry));
                }
                else
                {
                    Console.WriteLine(entry.FullPath);
                }
            }
        }

        static void DumpDirectories(IEnumerable<string> names)
        {
            Queue<Tuple<ObjectDirectory, string>> dumpList
                = new Queue<Tuple<ObjectDirectory, string>>(names.Select(s => new Tuple<ObjectDirectory, string>(null, s)));
            HashSet<string> dumpedDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            List<ObjectDirectoryEntry> totalEntries = new List<ObjectDirectoryEntry>();            

            while (dumpList.Count > 0)
            {
                Tuple<ObjectDirectory, string> name = dumpList.Dequeue();
                try
                {                    
                    using (ObjectDirectory directory = ObjectNamespace.OpenDirectory(name.Item1, name.Item2))
                    {
                        if (!dumpedDirs.Contains(directory.FullPath))
                        {
                            dumpedDirs.Add(directory.FullPath);
                            List<ObjectDirectoryEntry> sortedEntries = new List<ObjectDirectoryEntry>(directory.Entries);
                            sortedEntries.Sort();

                            string base_name = name.Item2.TrimEnd('\\');

                            IEnumerable<ObjectDirectoryEntry> objs = sortedEntries;

                            if (recursive)
                            {
                                foreach (ObjectDirectoryEntry entry in sortedEntries.Where(d => d.IsDirectory))
                                {
                                    dumpList.Enqueue(new Tuple<ObjectDirectory, string>(directory.Duplicate(), entry.ObjectName));
                                }
                            }

                            if (typeFilter.Count > 0)
                            {
                                objs = objs.Where(e => typeFilter.Contains(e.TypeName.ToLower()));
                            }

                            switch (format)
                            {
                                case OutputFormat.NameOnly:
                                    OutputNameOnly(directory, objs);
                                    break;
                                case OutputFormat.TypeGroup:
                                    totalEntries.AddRange(objs);
                                    break;
                                case OutputFormat.None:
                                default:
                                    OutputNone(directory, objs);
                                    break;
                            }
                        }
                    }
                }
                catch (NtException ex)
                {
                    Console.Error.WriteLine("Error querying {0} - {1}", name.Item2, ex.Message);
                }
            }

            switch (format)
            {
                case OutputFormat.TypeGroup:
                    OutputTypeGroup(totalEntries);
                    break;

            }
        }

        static string GetNamesForEnum(Type enumType)
        {
            return String.Join(",", Enum.GetNames(enumType).Select(s => s.ToLower()));
        }

        static void Main(string[] args)
        {
            try
            {
                OptionSet opts = new OptionSet() {
                        { "r", "Recursive tree directory listing",
                            v => recursive = v != null },
                        { "f|format=", "Specify output format [" + GetNamesForEnum(typeof(OutputFormat)) + "]",
                            v => format = (OutputFormat)Enum.Parse(typeof(OutputFormat), v, true) },
                        { "t|type=", "An object type to filter on, can be repeated",
                            v => typeFilter.Add(v.Trim().ToLower()) },
                        { "l", "Print symlink target", v => print_link = v != null },
                        { "sddl", "Print SDDL security descriptors for directories", v => print_sddl = v != null },
                        { "h|help",  "show this message and exit",
                           v => show_help = v != null },
                    };

                List<string> names = opts.Parse(args);

                if (names.Count == 0 || show_help)
                {
                    ShowHelp(opts);
                }
                else
                {
                    DumpDirectories(names);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }
}
