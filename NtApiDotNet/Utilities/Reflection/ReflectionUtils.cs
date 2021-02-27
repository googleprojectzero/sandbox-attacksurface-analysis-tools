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
using System.Collections.Concurrent;
using System.Linq;
using System.Reflection;

namespace NtApiDotNet.Utilities.Reflection
{
    /// <summary>
    /// Utilities for reflection.
    /// </summary>
    public static class ReflectionUtils
    {
        private readonly static ConcurrentDictionary<Tuple<Type, string>, string> _sdk_name_cache 
            = new ConcurrentDictionary<Tuple<Type, string>, string>();

        private static string GetSDKNameInternal(Type type, string member_name)
        {
            if (string.IsNullOrEmpty(member_name))
                return type.GetCustomAttribute<SDKNameAttribute>()?.Name;

            MemberInfo member = type.GetMember(member_name).FirstOrDefault();
            if (member == null)
                return null;
            return member.GetCustomAttribute<SDKNameAttribute>()?.Name;
        }

        private static string GetSDKNameCached(Type type, string member_name)
        {
            var key = Tuple.Create(type, member_name);
            return _sdk_name_cache.GetOrAdd(key, k => GetSDKNameInternal(k.Item1, k.Item2));
        }

        private static string GetSDKNameCached(Enum value)
        {
            return GetSDKNameCached(value.GetType(), value.ToString());
        }

        /// <summary>
        /// Get the SDK name for a type, if available.
        /// </summary>
        /// <param name="type">The type to get the name for.</param>
        /// <returns>The SDK name. Returns the name of the type if not available.</returns>
        public static string GetSDKName(Type type)
        {
            if (type is null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            return GetSDKNameCached(type, string.Empty) ?? type.Name;
        }

        /// <summary>
        /// Get the SDK name for an enum, if available.
        /// </summary>
        /// <param name="value">The enum to get the name for.</param>
        /// <returns>The SDK name. If the enum is a flags enum then will return the names joined with commas.</returns>
        public static string GetSDKName(Enum value)
        {
            if (value is null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            var sdk_name = GetSDKNameCached(value);
            if (sdk_name != null)
                return sdk_name;

            Type type = value.GetType();
            var parts = value.ToString().Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim());
            return string.Join(", ", parts.Select(s => GetSDKNameCached(type, s) ?? s));
        }

        /// <summary>
        /// Get the SDK name an object.
        /// </summary>
        /// <param name="value">The object to get the name from. If this isn't an Enum or Type then the Type of the object is used.</param>
        /// <returns>The SDK name.</returns>
        public static string GetSDKName(object value)
        {
            if (value is null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            if (value is Type type)
            {
                return GetSDKName(type);
            }
            else if (value is Enum en)
            {
                return GetSDKName(en);
            }
            return GetSDKName(value.GetType());
        }
    }
}
