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

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Utilities.Collections;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Security.Interop;

[StructLayout(LayoutKind.Sequential)]
internal struct SECURITY_CAPABILITIES
{
    public IntPtr AppContainerSid;
    public IntPtr Capabilities;
    public int CapabilityCount;
    public int Reserved;

    internal static SECURITY_CAPABILITIES Create(Sid package_sid, IEnumerable<Sid> capabilities, DisposableList resources)
    {
        SECURITY_CAPABILITIES caps = new()
        {
            AppContainerSid = resources.AddResource(package_sid.ToSafeBuffer()).DangerousGetHandle()
        };

        if (capabilities.Any())
        {
            SidAndAttributes[] cap_sids = capabilities.Select(s => new SidAndAttributes()
            {
                Sid = resources.AddResource(s.ToSafeBuffer()).DangerousGetHandle(),
                Attributes = GroupAttributes.Enabled
            }).ToArray();

            SafeHGlobalBuffer cap_buffer = resources.AddResource(new SafeHGlobalBuffer(Marshal.SizeOf(typeof(SidAndAttributes)) * cap_sids.Length));
            cap_buffer.WriteArray(0, cap_sids, 0, cap_sids.Length);
            caps.Capabilities = cap_buffer.DangerousGetHandle();
            caps.CapabilityCount = cap_sids.Length;
        }

        return caps;
    }
}
