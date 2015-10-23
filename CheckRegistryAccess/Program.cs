//  Copyright 2015 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using HandleUtils;
using Microsoft.Win32;
using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security;

namespace CheckRegistryAccess
{
    class Program
    {
        static bool _recursive = false;
        static bool _print_sddl = false;
        static bool _show_write_only = false;
        static HashSet<string> _walked = new HashSet<string>();        
        static ObjectTypeInfo _type;
        static NativeHandle _token;
        static uint _key_rights = 0;

        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("Usage: CheckRegistryAccess [options] key1 [key2..keyN]");            
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
        }

        static string AccessMaskToString(uint granted_access)
        {
            if (_type.HasFullPermission(granted_access))
            {
                return "Full Permission";
            }

            KeyAccessRights rights = (KeyAccessRights)(granted_access & 0xFFFF);
            StandardAccessRights standard = (StandardAccessRights)(granted_access & 0x1F0000);
            return String.Join(", ", new string[] { standard.ToString(), rights.ToString() });
        }

        static void CheckAccess(string name)
        {
            try
            {                
                byte[] sd = NativeBridge.GetNamedSecurityDescriptor(MapKeyName(name), "key");
                if (sd.Length > 0)
                {
                    uint granted_access = 0;

                    if (_key_rights != 0)
                    {
                        granted_access = NativeBridge.GetAllowedAccess(_token, _type, _key_rights, sd);
                    }
                    else
                    {
                        granted_access = NativeBridge.GetMaximumAccess(_token, _type, sd);
                    }

                    if (granted_access != 0)
                    {
                        // As we can get all the righs for the key get maximum
                        if (_key_rights != 0)
                        {
                            granted_access = NativeBridge.GetMaximumAccess(_token, _type, sd);
                        }

                        if (!_show_write_only || _type.HasWritePermission(granted_access))
                        {
                            Console.WriteLine("{0} : {1:X08} {2}", name, granted_access, AccessMaskToString(granted_access));
                            if (_print_sddl)
                            {
                                Console.WriteLine("{0}", NativeBridge.GetStringSecurityDescriptor(sd));
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
            }
        }

        static void DumpKey(RegistryKey key)
        {            
            if (_walked.Contains(key.Name.ToLower()))
            {
                return;
            }

            _walked.Add(key.Name.ToLower());

            try
            {
                CheckAccess(key.Name);

                if (_recursive)
                {
                    foreach(string name in key.GetSubKeyNames())                    
                    {
                        RegistryKey subkey = null;
                        try
                        {
                            subkey = key.OpenSubKey(name, false);
                            if (subkey != null)
                            {
                                DumpKey(subkey);
                            }
                        }
                        catch (SecurityException)
                        {
                        }
                        finally
                        {
                            if (subkey != null)
                            {
                                subkey.Close();
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error dumping key {0} {1}", key.Name, ex.Message);
            }
        }

        static string MapKeyName(string fullpath)
        {
            string mapped = "";
            string[] nameparts = fullpath.Split(new char[] { '\\' }, 2);

            if (nameparts.Length == 0)
            {
                throw new ArgumentException("Invalid key name");
            }

            switch (nameparts[0].ToLower())
            {
                case "hkey_local_machine":
                    mapped = "MACHINE";
                    break;
                case "hkey_current_user":
                    mapped = "CURRENT_USER";
                    break;
                case "hkey_users":
                    mapped = "USERS";
                    break;
                case "hkey_classes_root":
                    mapped = "CLASSES_ROOT";
                    break;
                default:
                    throw new ArgumentException(String.Format("Invalid root keyname {0}", nameparts[0]));
            }

            if(nameparts.Length > 1)
            {
                return mapped + "\\" + nameparts[1];
            }
            else
            {
                return mapped + "\\";
            }
        }

        static RegistryKey OpenKey(string name)
        {
            RegistryHive hive = RegistryHive.LocalMachine;

            string[] nameparts = name.Split(new char[] { '\\' }, 2);

            if (nameparts.Length == 0)
            {
                throw new ArgumentException("Invalid key name");
            }

            switch (nameparts[0].ToLower())
            {
                case "hkey_local_machine":
                    hive = RegistryHive.LocalMachine;
                    break;
                case "hkey_current_user":
                    hive = RegistryHive.CurrentUser;
                    break;
                case "hkey_users":
                    hive = RegistryHive.Users;
                    break;
                case "hkey_classes_root":
                    hive = RegistryHive.ClassesRoot;
                    break;
                default:
                    throw new ArgumentException(String.Format("Invalid root keyname {0}", nameparts[0]));
            }

            RegistryKey rootKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);

            if ((nameparts.Length == 1) || (String.IsNullOrWhiteSpace(nameparts[1])))
            {
                return rootKey;
            }
            else
            {
                RegistryKey ret = rootKey.OpenSubKey(nameparts[1], false);

                rootKey.Close();

                return ret;
            }
        }

        static uint ParseRight(string name, Type enumtype)
        {
            return (uint)Enum.Parse(enumtype, name, true);
        }

        static void Main(string[] args)
        {
            bool show_help = false;

            int pid = Process.GetCurrentProcess().Id;

            OptionSet opts = new OptionSet() {
                        { "r", "Recursive tree directory listing",  
                            v => _recursive = v != null },                                  
                        { "sddl", "Print full SDDL security descriptors", v => _print_sddl = v != null },
                        { "p|pid=", "Specify a PID of a process to impersonate when checking", v => pid = int.Parse(v.Trim()) },
                        { "w", "Show only write permissions granted", v => _show_write_only = v != null },
                        { "k=", String.Format("Filter on a specific key right [{0}]", 
                            String.Join(",", Enum.GetNames(typeof(KeyAccessRights)))), v => _key_rights |= ParseRight(v, typeof(KeyAccessRights)) },  
                        { "s=", String.Format("Filter on a standard right [{0}]", 
                            String.Join(",", Enum.GetNames(typeof(StandardAccessRights)))), v => _key_rights |= ParseRight(v, typeof(StandardAccessRights)) },  
                        { "x=", "Specify a base path to exclude from recursive search", v => _walked.Add(v.ToLower()) },
                        { "h|help",  "show this message and exit", v => show_help = v != null },
                    };

            List<string> paths = opts.Parse(args);

            if (show_help || (paths.Count == 0))
            {
                ShowHelp(opts);
            }
            else
            {
                try
                {
                    _type = ObjectTypeInfo.GetTypeByName("key");
                    _token = NativeBridge.OpenProcessToken(pid);                    

                    foreach (string path in paths)
                    {
                        RegistryKey key = OpenKey(path);

                        if (key != null)
                        {
                            try
                            {
                                DumpKey(key);
                            }
                            finally
                            {
                                key.Close();
                            }
                        }                        
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
            }
        }
    }
}
