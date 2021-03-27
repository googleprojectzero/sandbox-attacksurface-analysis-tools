//  Copyright 2021 Google Inc. All Rights Reserved.
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

using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Image
{
    internal static class ImageUtils
    {
        public static string GetResourceString(IntPtr ptr)
        {
            if (ptr.ToInt64() < 0x10000)
            {
                return $"#{ptr}";
            }
            return Marshal.PtrToStringUni(ptr);
        }

        public static WellKnownImageResourceType GetWellKnownType(IntPtr ptr)
        {
            if (ptr.ToInt64() < 0x10000 && Enum.IsDefined(typeof(WellKnownImageResourceType), ptr.ToInt32()))
            {
                return (WellKnownImageResourceType)ptr.ToInt32();
            }

            return WellKnownImageResourceType.Unknown;
        }

        public static bool TryParseId(string name, out int type_id)
        {
            type_id = 0;
            if (!name.StartsWith("#") || name.Length < 2 || !char.IsDigit(name[1])) 
                return false;

            int index = name.IndexOf(' ');
            if (index > 0)
            {
                name = name.Substring(1, index - 1);
            }
            else
            {
                name = name.Substring(1);
            }
            
            return int.TryParse(name, out type_id);
        }
    }
}
