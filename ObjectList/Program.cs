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

namespace ObjectList
{
    class Program
    {
        enum OutputFormat
        {
            Default,
            NameOnly,
            TypeGroup,
        }

        sealed class DirectoryQueueEntry : IDisposable
        {
            public NtDirectory Directory { get; private set; }
            public string Name { get; private set; }
            public DirectoryQueueEntry(NtDirectory directory, string name)
            {
                Directory = directory;
                Name = name;
            }

            public NtDirectory OpenDirectory()
            {
                if (Name.StartsWith(@"\") || Directory != null)
                {
                    return NtDirectory.Open(Name, Directory, DirectoryAccessRights.MaximumAllowed);
                }
                else
                {
                    return NtDirectory.OpenPrivateNamespace(BoundaryDescriptor.CreateFromString(Name));
                }
            }

            void IDisposable.Dispose()
            {
                if (Directory != null)
                {
                    Directory.Close();
                }
            }
        }

        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("Usage: ObjectList [options] path1 [path2..pathN]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
        }

        static string ReadSecurityDescriptor(NtObject obj)
        {
            try
            {
                if (obj.IsAccessMaskGranted(GenericAccessRights.ReadControl))
                {
                    return obj.Sddl;
                }
            }
            catch (NtException)
            {
            }
            return String.Empty;
        }

        static void OutputDefault(NtDirectory base_dir, IEnumerable<ObjectDirectoryInformation> entries, bool print_sddl, bool print_link)
        {
            if (print_sddl)
            {
                Console.WriteLine("SDDL: {0} -> {1}", base_dir.FullPath, ReadSecurityDescriptor(base_dir));
            }

            foreach (var entry in entries.Where(e => e.IsDirectory))
            {
                Console.WriteLine(@"<DIR> {0}", entry.FullPath);
            }

            foreach (var entry in entries.Where(e => !e.IsDirectory))
            {
                if (entry.IsSymbolicLink && print_link)
                {
                    Console.WriteLine("      {0} -> {1}", entry.FullPath, entry.SymbolicLinkTarget);
                }
                else
                {
                    Console.WriteLine("      {0} ({1})", entry.FullPath, entry.NtTypeName);
                }
            }
        }

        static void OutputTypeGroup(IEnumerable<ObjectDirectoryInformation> entries)
        {
            var groups = entries.GroupBy(e => e.NtTypeName, StringComparer.OrdinalIgnoreCase);
            foreach (var group in groups)
            {
                Console.WriteLine("Type: {0} (Total: {1})", group.Key, group.Count());
                foreach (var entry in group)
                {
                    Console.WriteLine(entry.FullPath);
                }
                Console.WriteLine();
            }
        }

        static void OutputNameOnly(IEnumerable<ObjectDirectoryInformation> entries)
        {
            foreach (ObjectDirectoryInformation entry in entries)
            {
                Console.WriteLine(entry.FullPath);
            }
        }

        private static void DumpDirectories(IEnumerable<string> names, bool recursive, bool print_link, 
            bool print_sddl, OutputFormat format, HashSet<string> type_filter)
        {
            Queue<DirectoryQueueEntry> dump_queue
                = new Queue<DirectoryQueueEntry>(names.Select(s => new DirectoryQueueEntry(null, s)));
            HashSet<string> dumped_dirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            List<ObjectDirectoryInformation> total_entries = new List<ObjectDirectoryInformation>();

            while (dump_queue.Count > 0)
            {
                using (DirectoryQueueEntry entry = dump_queue.Dequeue())
                {
                    try
                    {
                        using (NtDirectory directory = entry.OpenDirectory())
                        {
                            if (!directory.IsAccessGranted(DirectoryAccessRights.Query))
                            {
                                continue;
                            }

                            if (dumped_dirs.Add(directory.FullPath))
                            {
                                IEnumerable<ObjectDirectoryInformation> objs = directory.Query().OrderBy(e => Tuple.Create(e.Name, e.NtTypeName));

                                if (recursive)
                                {
                                    foreach (var next_entry in objs.Where(d => d.IsDirectory))
                                    {
                                        dump_queue.Enqueue(new DirectoryQueueEntry(directory.Duplicate(), next_entry.Name));
                                    }
                                }

                                if (type_filter.Count > 0)
                                {
                                    objs = objs.Where(e => type_filter.Contains(e.NtTypeName));
                                }

                                switch (format)
                                {
                                    case OutputFormat.NameOnly:
                                        OutputNameOnly(objs);
                                        break;
                                    case OutputFormat.TypeGroup:
                                        total_entries.AddRange(objs);
                                        break;
                                    case OutputFormat.Default:
                                    default:
                                        OutputDefault(directory, objs, print_sddl, print_link);
                                        break;
                                }
                            }
                        }
                    }
                    catch (NtException ex)
                    {
                        Console.Error.WriteLine("Error querying {0} - {1}", entry.Name, ex.Message);
                    }
                }
            }

            switch (format)
            {
                case OutputFormat.TypeGroup:
                    OutputTypeGroup(total_entries);
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
                bool show_help = false;
                bool recursive = false;
                bool print_link = false;
                bool print_sddl = false;
                OutputFormat format = OutputFormat.Default;
                HashSet<string> type_filter = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                OptionSet opts = new OptionSet() {
                        { "r", "Recursive tree directory listing",
                            v => recursive = v != null },
                        { "f|format=", "Specify output format [" + GetNamesForEnum(typeof(OutputFormat)) + "]",
                            v => format = (OutputFormat)Enum.Parse(typeof(OutputFormat), v, true) },
                        { "t|type=", "An object type to filter on, can be repeated",
                            v => type_filter.Add(v.Trim()) },
                        { "l", "Print symlink target", v => print_link = v != null },
                        { "sddl", "Print SDDL security descriptors for directories", v => print_sddl = v != null },
                        { "h|help",  "show this message and exit",
                           v => show_help = v != null },
                    };

                List<string> names = opts.Parse(args);

                if ((print_link || print_sddl) && format != OutputFormat.Default)
                {
                    Console.WriteLine("Printing symbolic link targets or SDDL only works in default output mode");
                    show_help = true;
                }

                if (names.Count == 0 || show_help)
                {
                    ShowHelp(opts);
                }
                else
                {
                    DumpDirectories(names, recursive, print_link, print_sddl, format, type_filter);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }
}
