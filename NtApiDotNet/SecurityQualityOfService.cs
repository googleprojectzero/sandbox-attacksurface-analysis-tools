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

using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    public enum SecurityImpersonationLevel
    {
        Anonymous = 0,
        Identification = 1,
        Impersonation = 2,
        Delegation = 3
    }

    public enum SecurityContextTrackingMode : byte
    {
        Static = 0,
        Dynamic = 1
    }

    [StructLayout(LayoutKind.Sequential)]
    public sealed class SecurityQualityOfService
    {
        int Length;
        public SecurityImpersonationLevel ImpersonationLevel;
        public SecurityContextTrackingMode ContextTrackingMode;
        [MarshalAs(UnmanagedType.U1)]
        public bool EffectiveOnly;

        public SecurityQualityOfService()
        {
            Length = Marshal.SizeOf(this);
        }
    }

    public struct SecurityQualityOfServiceStruct
    {
        public int Length;
        public SecurityImpersonationLevel ImpersonationLevel;
        public SecurityContextTrackingMode ContextTrackingMode;
        [MarshalAs(UnmanagedType.U1)]
        public bool EffectiveOnly;
    }
#pragma warning restore 1591
}
