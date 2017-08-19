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
using System.Diagnostics;

namespace CheckRegistryAccess
{
    class Program
    {
        static bool _recursive = false;
        static bool _print_sddl = false;
        static bool _show_write_only = false;
        static HashSet<string> _walked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        static uint _key_rights = 0;
        static bool _map_to_generic = false;

        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("Usage: CheckRegistryAccess [options] key1 [key2..keyN]");            
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
            Console.WriteLine(@"Key names can be in win32 form (hkey_local_machine\blah) or native (\Registry\Machine\blah");
        }

        static void CheckAccess(NtToken token, NtKey key)
        {
            NtType type = key.NtType;
            if (!key.IsAccessGranted(KeyAccessRights.ReadControl))
            {
                return;
            }

            SecurityDescriptor sd = key.SecurityDescriptor;
            AccessMask granted_access;

            if (_key_rights != 0)
            {
                granted_access = NtSecurity.GetAllowedAccess(token, type, 
                            _key_rights, sd.ToByteArray());
            }
            else
            {
                granted_access = NtSecurity.GetMaximumAccess(token, type, sd.ToByteArray());
            }

            if (!granted_access.IsEmpty)
            {
                // As we can get all the rights for the key get maximum
                if (_key_rights != 0)
                {
                    granted_access = NtSecurity.GetMaximumAccess(token, type, sd.ToByteArray());
                }

                if (!_show_write_only || type.HasWritePermission(granted_access))
                {
                    Console.WriteLine("{0} : {1:X08} {2}", key.FullPath, granted_access, AccessMaskToString(granted_access, type));
                    if (_print_sddl)
                    {
                        Console.WriteLine("{0}", sd.ToSddl());
                    }
                }
            }
        }

        private static string AccessMaskToString(AccessMask granted_access, NtType type)
        {
            return NtObjectUtils.GrantedAccessAsString(granted_access, type.GenericMapping, typeof(KeyAccessRights), _map_to_generic);
        }

        static void DumpKey(NtToken token, NtKey key)
        {
            string key_name = key.FullPath;
            if (_walked.Contains(key_name))
            {
                return;
            }

            _walked.Add(key_name);

            try
            {
                CheckAccess(token, key);

                if (_recursive && key.IsAccessGranted(KeyAccessRights.EnumerateSubKeys))
                {
                    using (var keys = key.QueryAccessibleKeys(KeyAccessRights.MaximumAllowed).ToDisposableList())
                    {
                        foreach (NtKey subkey in keys)
                        {
                            DumpKey(token, subkey);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error dumping key {0} {1}", key.FullPath, ex.Message);
            }
        }

        static NtKey OpenKey(string name)
        {
            if (!name.StartsWith(@"\"))
            {
                name = NtKeyUtils.Win32KeyNameToNt(name);
            }

            using (ObjectAttributes obja = new ObjectAttributes(name, 
                AttributeFlags.CaseInsensitive | AttributeFlags.OpenLink, null))
            {
                return NtKey.Open(obja, KeyAccessRights.MaximumAllowed, 0);
            }
        }

        static uint ParseRight(string name, Type enumtype)
        {
            return (uint)Enum.Parse(enumtype, name, true);
        }

        static void PrintDeprecationWarning()
        {
            ConsoleColor color = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Error.WriteLine("This utility is deprecated. Please use the PowerShell Get-AccessibleKey cmdlet instead");
            Console.ForegroundColor = color;
        }

        static void Main(string[] args)
        {
            bool show_help = false;

            int pid = Process.GetCurrentProcess().Id;

            try
            {
                PrintDeprecationWarning();

                OptionSet opts = new OptionSet() {
                        { "r", "Recursive tree directory listing",  
                            v => _recursive = v != null },                                  
                        { "sddl", "Print full SDDL security descriptors", v => _print_sddl = v != null },
                        { "p|pid=", "Specify a PID of a process to impersonate when checking", v => pid = int.Parse(v.Trim()) },
                        { "w", "Show only write permissions granted", v => _show_write_only = v != null },
                        { "k=", String.Format("Filter on a specific right [{0}]", 
                            String.Join(",", Enum.GetNames(typeof(KeyAccessRights)))), v => _key_rights |= ParseRight(v, typeof(KeyAccessRights)) },  
                        { "x=", "Specify a base path to exclude from recursive search", v => _walked.Add(v.ToLower()) },
                        { "g", "Map access mask to generic rights.", v => _map_to_generic = v != null },
                        { "h|help",  "show this message and exit", v => show_help = v != null },
                    };

                List<string> paths = opts.Parse(args);

                if (show_help || (paths.Count == 0))
                {
                    ShowHelp(opts);
                }
                else
                {
                    using (NtToken token = NtToken.OpenProcessToken(pid))
                    {
                        foreach (string path in paths)
                        {
                            try
                            {
                                using (NtKey key = OpenKey(path))
                                {
                                    DumpKey(token, key);
                                }
                            }
                            catch (NtException ex)
                            {
                                Console.Error.WriteLine("Error opening key: {0} - {1}", path, ex.Message);
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
            }
        }
    }
}
