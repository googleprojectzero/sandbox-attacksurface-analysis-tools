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
        private int _length;
        private SecurityImpersonationLevel _imp_level;
        private SecurityContextTrackingMode _tracking_mode;
        [MarshalAs(UnmanagedType.U1)]
        private bool _effective_only;

        public SecurityImpersonationLevel ImpersonationLevel { get { return _imp_level; } set { _imp_level = value; } }
        public SecurityContextTrackingMode ContextTrackingMode { get { return _tracking_mode; } set { _tracking_mode = value; } }
        public bool EffectiveOnly { get { return _effective_only; } set { _effective_only = value; } }

        public SecurityQualityOfService()
        {
            _length = Marshal.SizeOf(this);
        }

        public SecurityQualityOfService(SecurityImpersonationLevel imp_level, 
            SecurityContextTrackingMode tracking_mode, 
            bool effective_only) : this()
        {
            _imp_level = imp_level;
            _tracking_mode = tracking_mode;
            _effective_only = effective_only;
        }

        internal SecurityQualityOfServiceStruct ToStruct()
        {
            return new SecurityQualityOfServiceStruct(ImpersonationLevel, ContextTrackingMode, EffectiveOnly);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecurityQualityOfServiceStruct
    {
        public int Length;
        public SecurityImpersonationLevel ImpersonationLevel;
        public SecurityContextTrackingMode ContextTrackingMode;
        [MarshalAs(UnmanagedType.U1)]
        public bool EffectiveOnly;

        public SecurityQualityOfServiceStruct(SecurityImpersonationLevel impersonation_level,
            SecurityContextTrackingMode context_tracking_mode, bool effective_only)
        {
            Length = Marshal.SizeOf(typeof(SecurityQualityOfServiceStruct));
            ImpersonationLevel = impersonation_level;
            ContextTrackingMode = context_tracking_mode;
            EffectiveOnly = effective_only;
        }
    }
#pragma warning restore 1591
}
