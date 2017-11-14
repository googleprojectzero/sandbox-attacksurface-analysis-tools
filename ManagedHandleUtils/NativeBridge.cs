//  Copyright 2016 Google Inc. All Rights Reserved.
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

using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace SandboxAnalysisUtils
{
    public static class NativeBridge
    {
        static bool IsValidMask(uint mask, uint valid_mask)
        {
            if (mask == 0)
            {
                return false;
            }

            // Filter out generic access etc.
            if ((mask & ~valid_mask) != 0)
            {
                return false;
            }

            // Check if the mask only has a single bit set.
            if ((mask & (mask - 1)) != 0)
            {
                return false;
            }

            return true;
        }

        static void AddEnumToDictionary(Dictionary<uint, String> access, Type enumType, uint valid_mask)
        {
            Regex re = new Regex("([A-Z])");

            foreach(uint mask in Enum.GetValues(enumType))
            {
                if (IsValidMask(mask, valid_mask))
                {
                    access.Add(mask, re.Replace(Enum.GetName(enumType, mask), " $1").Trim());
                }
            }
        }

        static Dictionary<uint, String> GetMaskDictionary(NtType type)
        {
            Dictionary<uint, String> access = new Dictionary<uint, String>();
                        
            AddEnumToDictionary(access, type.AccessRightsType, type.ValidAccess.Access);

            return access;
        }
        
        [DllImport("aclui.dll")]
        static extern bool EditSecurity(IntPtr hwndOwner, ISecurityInformation psi);
        
        public static void EditSecurity(IntPtr hwnd, NtObject handle, string object_name, bool read_only)
        {
            Dictionary<uint, String> access = GetMaskDictionary(handle.NtType);

            using (SecurityInformationImpl impl = new SecurityInformationImpl(object_name, handle, access,
               handle.NtType.GenericMapping, read_only))
            {
                EditSecurity(hwnd, impl);
            }
        }

        public static void EditSecurity(IntPtr hwnd, string name, SecurityDescriptor sd, NtType type)
        {
            Dictionary<uint, String> access = GetMaskDictionary(type);
            using (var impl = new SecurityInformationImpl(name, sd, access, type.GenericMapping))
            {
                EditSecurity(hwnd, impl);
            }
        }
    }
}
