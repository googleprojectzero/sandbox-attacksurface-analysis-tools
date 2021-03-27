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

namespace NtApiDotNet.Win32.Image
{
    /// <summary>
    /// Image resource type.
    /// </summary>
    public struct ImageResourceType
    {
        internal IntPtr NamePtr { get; }

        /// <summary>
        /// The name of the resource as a string.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// The well known type, is available (otherwise set to UNKNOWN)
        /// </summary>
        public WellKnownImageResourceType WellKnownType { get; }

        internal ImageResourceType(IntPtr ptr)
        {
            NamePtr = ptr;
            Name = ImageUtils.GetResourceString(ptr);
            WellKnownType = ImageUtils.GetWellKnownType(ptr);
        }

        internal ImageResourceType(string name)
        {
            if (ImageUtils.TryParseId(name, out int type_id))
            {
                NamePtr = new IntPtr(type_id);
                Name = $"#{type_id}";
                if (Enum.IsDefined(typeof(WellKnownImageResourceType), type_id))
                {
                    WellKnownType = (WellKnownImageResourceType)type_id;
                }
                else
                {
                    WellKnownType = WellKnownImageResourceType.Unknown;
                }
            }
            else
            {
                NamePtr = IntPtr.Zero;
                Name = name;
                WellKnownType = WellKnownImageResourceType.Unknown;
            }
        }

        internal ImageResourceType(WellKnownImageResourceType name)
        {
            NamePtr = new IntPtr((int)name);
            Name = $"#{(int)name}";
            WellKnownType = name;
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The name of the type.</returns>
        public override string ToString()
        {
            return WellKnownType != WellKnownImageResourceType.Unknown ? $"{Name} ({WellKnownType})": Name;
        }
    }
}
