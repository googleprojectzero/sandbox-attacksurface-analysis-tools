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
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace CheckDeviceAccess
{
    class Program
    {
        static bool _recursive;
        static int _pid;
        static bool _show_errors;
        static bool _identify_only;
        static bool _open_as_dir;
        static bool _filter_direct;

        class CheckResult
        {
            public string Path { get; private set; }
            public NtStatus Status { get; private set; }
            public FileDeviceType DeviceType { get; private set; }

            public override bool Equals(object obj)
            {
                if (base.Equals(obj))
                {
                    return true;
                }
                CheckResult result = obj as CheckResult;
                if (result == null)
                {
                    return false;
                }
                return Path.Equals(result.Path, StringComparison.OrdinalIgnoreCase) && Status == result.Status;
            }

            public override int GetHashCode()
            {
                return Path.ToLowerInvariant().GetHashCode() ^ Status.GetHashCode();
            }

            public CheckResult(string path, NtStatus status, FileDeviceType device_type)
            {
                Path = path;
                Status = status;
                DeviceType = device_type;
            }
        }

        static List<string> FindDeviceObjects(IEnumerable<string> names)
        {
            Queue<string> dumpList = new Queue<string>(names);
            HashSet<string> dumpedDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            List<string> totalEntries = new List<string>();

            while (dumpList.Count > 0)
            {
                string name = dumpList.Dequeue();
                try
                {
                    ObjectDirectory directory = ObjectNamespace.OpenDirectory(null, name);

                    if (!dumpedDirs.Contains(directory.FullPath))
                    {
                        dumpedDirs.Add(directory.FullPath);
                        List<ObjectDirectoryEntry> sortedEntries = new List<ObjectDirectoryEntry>(directory.Entries);
                        sortedEntries.Sort();

                        string base_name = name.TrimEnd('\\');

                        IEnumerable<ObjectDirectoryEntry> objs = sortedEntries;

                        if (_recursive)
                        {
                            foreach (ObjectDirectoryEntry entry in sortedEntries.Where(d => d.IsDirectory))
                            {
                                dumpList.Enqueue(entry.FullPath);
                            }
                        }

                        totalEntries.AddRange(objs.Where(e => e.TypeName.Equals("device", StringComparison.OrdinalIgnoreCase)).Select(e => e.FullPath));    
                    }
                }
                catch (NtException ex)
                {
                    int error = NtRtl.RtlNtStatusToDosError(ex.Status);
                    if (NtRtl.RtlNtStatusToDosError(ex.Status) == 6)
                    {
                        // Add name in case it's an absolute name, not in a directory
                        totalEntries.Add(name);
                    }
                    else
                    {
                    }
                }
            }

            return totalEntries;
        }

        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("Usage: CheckDeviceAccess [options] dir1 [dir2..dirN]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
        }

        static bool IgnoreError(NtStatus status)
        {
            switch (NtRtl.RtlNtStatusToDosError(status))
            {
                case 1:
                case 5:
                    return true;
            }
            return false;
        }

        static void PrintError(string name, NtException ex)
        {
            if (_show_errors && !IgnoreError(ex.Status))
            {
                Console.Error.WriteLine("Error checking {0} - {1}", name, ex.Message);
            }
        }

        static CheckResult CheckDevice(string name, bool writable, EaBuffer ea_buffer)
        {
            CheckResult result = new CheckResult(name, NtStatus.STATUS_INVALID_PARAMETER, FileDeviceType.UNKNOWN);
            try
            {
                using (var imp = NtToken.Impersonate(_pid,
                    _identify_only ? SecurityImpersonationLevel.Identification : SecurityImpersonationLevel.Impersonation))
                {
                    FileAccessRights access_mask = FileAccessRights.GenericRead;
                    if (writable)
                    {
                        access_mask |= FileAccessRights.GenericWrite;
                    }

                    FileOpenOptions opts = _open_as_dir ? FileOpenOptions.DirectoryFile : FileOpenOptions.NonDirectoryFile;
                    using (NtFile file = NtFile.Create(name, null, access_mask, NtApiDotNet.FileAttributes.Normal, 
                        FileShareMode.All, opts, FileDisposition.Open, ea_buffer))
                    {
                        result = new CheckResult(name, NtStatus.STATUS_SUCCESS, file.DeviceType);
                    }
                }
            }
            catch (NtException ex)
            {
                result = new CheckResult(name, ex.Status, FileDeviceType.UNKNOWN);
            }

            return result;
        }
        
        static string GetSymlinkTarget(ObjectDirectoryEntry entry)
        {
            try
            {
                using (NtSymbolicLink link = NtSymbolicLink.Open(entry.FullPath, null))
                {
                    return link.Target;
                }
            }
            catch (NtException)
            {
                return "";
            }
        }

        static Dictionary<string, string> FindSymlinks()
        {
            Queue<string> dumpList = new Queue<string>(new string[] {"\\"});
            HashSet<string> dumpedDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Dictionary<string, string> symlinks = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            while (dumpList.Count > 0)
            {
                string name = dumpList.Dequeue();
                try
                {
                    ObjectDirectory directory = ObjectNamespace.OpenDirectory(null, name);

                    if (!dumpedDirs.Contains(directory.FullPath))
                    {
                        dumpedDirs.Add(directory.FullPath);
                        List<ObjectDirectoryEntry> sortedEntries = new List<ObjectDirectoryEntry>(directory.Entries);
                        sortedEntries.Sort();

                        string base_name = name.TrimEnd('\\');

                        IEnumerable<ObjectDirectoryEntry> objs = sortedEntries;
                        
                        foreach (ObjectDirectoryEntry entry in sortedEntries.Where(d => d.IsDirectory))
                        {
                            dumpList.Enqueue(entry.FullPath);
                        }

                        foreach (ObjectDirectoryEntry entry in sortedEntries.Where(d => d.IsSymlink))
                        {
                            symlinks[GetSymlinkTarget(entry)] = entry.FullPath;
                        }
                    }
                }
                catch (NtException)
                {
                }
            }

            return symlinks;
        }

        static void DumpList(IEnumerable<CheckResult> results, bool map_to_symlink, Dictionary<string, string> symlinks)
        {
            int count = 0;
            foreach (CheckResult result in results)
            {
                if ((!result.Status.IsSuccess() && !_show_errors) || IgnoreError(result.Status))
                {
                    continue;
                }

                count++;

                if (map_to_symlink && symlinks.ContainsKey(result.Path))
                {
                    Console.WriteLine("{0} -> {1} - {2} {3}", symlinks[result.Path], result.Path, result.DeviceType, result.Status);
                }
                else
                {
                    Console.WriteLine("{0} - {1} {2}", result.Path, result.DeviceType, result.Status);
                }
            }
            Console.WriteLine("Total Count: {0}", count);
        }

        static void Main(string[] args)
        {
            bool show_help = false;
            bool map_to_symlink = false;
            bool readable = false;
            bool ea_buffer = false;
            string suffix = "XYZ";
            string namelist = null;

            _pid = Process.GetCurrentProcess().Id;

            try
            {
                OptionSet opts = new OptionSet() {
                        { "r", "Recursive tree directory listing",  
                            v => _recursive = v != null },          
                        { "l", "Try and map device names to a symlink", v => map_to_symlink = v != null },
                        { "p|pid=", "Specify a PID of a process to impersonate when checking", v => _pid = int.Parse(v.Trim()) },
                        { "suffix=", "Specify the suffix for the namespace search", v => suffix = v },
                        { "namelist=", "Specify a text file with a list of names", v => namelist = v },
                        { "ea", "Try and show only devices with accept an EA buffer", v => ea_buffer = v != null },
                        { "e", "Display errors when trying devices, ignores Access Denied", v => _show_errors = v != null },
                        { "i", "Use an identify level token when impersonating", v => _identify_only = v != null },
                        { "d", "Try opening devices as directories rather than files", v => _open_as_dir = v != null },
                        { "f", "Filter out devices which could be opened direct and via namespace", v => _filter_direct = v != null },
                        { "readonly", "Show devices which can be opened for read access instead of write", v => readable = v != null },
                        { "h|help",  "show this message and exit", 
                           v => show_help = v != null },
                    };

                List<string> names = opts.Parse(args);

                if (namelist != null)
                {
                    names.AddRange(File.ReadAllLines(namelist));
                }

                if (names.Count == 0 || show_help)
                {
                    ShowHelp(opts);
                }
                else
                {
                    List<string> device_objs;

                    if (_recursive)
                    {
                        device_objs = FindDeviceObjects(names);
                    }
                    else
                    {
                        device_objs = names;
                    }

                    if (device_objs.Count > 0)
                    {
                        EaBuffer ea = null;
                        if (ea_buffer)
                        {
                            ea = new EaBuffer();
                            ea.AddEntry("GARBAGE", new byte[16], EaBufferEntryFlags.NeedEa);
                        }

                        IEnumerable<CheckResult> write_normal = device_objs.Select(n => CheckDevice(n, !readable, ea));
                        IEnumerable<CheckResult> write_namespace = device_objs.Select(n => CheckDevice(n + "\\" + suffix, !readable, ea));
                        Dictionary<string, string> symlinks = FindSymlinks();

                        if (ea_buffer)
                        {
                            _show_errors = true;
                            write_normal = write_normal.Where(e => e.Status == NtStatus.STATUS_INVALID_PARAMETER);
                            write_namespace = write_namespace.Where(e => e.Status == NtStatus.STATUS_INVALID_PARAMETER);
                        }

                        if (_filter_direct)
                        {
                            Console.WriteLine("Namespace Only");
                            HashSet<string> normal = new HashSet<string>(write_normal.Where(r => r.Status.IsSuccess()).Select(r => r.Path), StringComparer.OrdinalIgnoreCase);
                            DumpList(write_namespace.Where(r => !normal.Contains(r.Path)), map_to_symlink, symlinks);
                        }
                        else
                        {
                            Console.WriteLine("{0} Access", readable ? "Read" : "Write");
                            DumpList(write_normal, map_to_symlink, symlinks);
                            Console.WriteLine();
                            Console.WriteLine("{0} Access with Namespace", readable ? "Read" : "Write");
                            DumpList(write_namespace, map_to_symlink, symlinks);
                        }
                    }
                    else
                    {
                        Console.WriteLine("No device names specified");
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
