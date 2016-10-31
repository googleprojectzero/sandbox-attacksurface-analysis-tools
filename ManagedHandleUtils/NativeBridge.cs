//  Copyright 2016 Google Inc. All Rights Reserved.
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

using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace HandleUtils
{
    public static class NativeBridge
    {
        static void AddEnumToDictionary(Dictionary<uint, String> access, Type enumType)
        {
            Regex re = new Regex("([A-Z])");

            foreach(uint mask in Enum.GetValues(enumType))
            {
                access.Add(mask, re.Replace(Enum.GetName(enumType, mask), " $1").Trim());
            }
        }

        static Dictionary<uint, String> GetMaskDictionary(Type enumType)
        {
            Dictionary<uint, String> access = new Dictionary<uint, String>();
                        
            AddEnumToDictionary(access, enumType);

            return access;
        }
        
        [DllImport("aclui.dll")]
        static extern bool EditSecurity(IntPtr hwndOwner, ISecurityInformation psi);

        static Type TypeNameToEnum(string name)
        {
            switch(name.ToLower())
            {
                case "directory": return typeof(DirectoryAccessRights);
                case "event": return typeof(EventAccessRights);
                case "section": return typeof(SectionAccessRights);
                case "mutant": return typeof(MutantAccessRights);
                case "semaphore": return typeof(SemaphoreAccessRights);
                case "job": return typeof(JobAccessRights);
                case "symboliclink": return typeof(SymbolicLinkAccessRights);
                case "file":
                case "device":
                    return typeof(FileAccessRights);
                case "process":
                    return typeof(ProcessAccessRights);
                case "token":
                    return typeof(TokenAccessRights);
                case "thread":
                    return typeof(ThreadAccessRights);
                default:
                    throw new ArgumentException("Can't get type for access rights");
            }
        }

        public static void EditSecurity(IntPtr hwnd, NtObject handle, string object_name, string typeName, bool writeable)
        {
            NtType typeInfo = NtType.GetTypeByName(typeName);
            Dictionary<uint, String> access = GetMaskDictionary(TypeNameToEnum(typeName));

            using (SecurityInformationImpl impl = new SecurityInformationImpl(object_name, handle, access,
               typeInfo.GenericMapping))
            {
                EditSecurity(hwnd, impl);
            }
        }
    }
}
