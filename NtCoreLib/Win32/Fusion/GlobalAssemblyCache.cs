//  Copyright 2024 Google LLC. All Rights Reserved.
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

using NtCoreLib.Win32.Fusion.Interop;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;

namespace NtCoreLib.Win32.Fusion;

/// <summary>
/// Class to access the global assembly cache.
/// </summary>
public static class GlobalAssemblyCache
{
    /// <summary>
    /// Get the list of assembly names in the cache.
    /// </summary>
    /// <returns>The list of assembly names.</returns>
    public static IEnumerable<AssemblyName> GetNames()
    {
        NativeMethods.CreateAssemblyEnum(out IAssemblyEnum e, null, null, ASM_CACHE_FLAGS.ASM_CACHE_GAC, IntPtr.Zero);
        while (e.GetNextAssembly(IntPtr.Zero, out IAssemblyName name, 0) == 0)
        {
            StringBuilder builder = new(1000);
            int len = 1000;

            name.GetDisplayName(builder, ref len, ASM_DISPLAY_FLAGS.ASM_DISPLAYF_FULL);
            builder.Length = len;
            yield return new AssemblyName(builder.ToString());
        }
    }
}
