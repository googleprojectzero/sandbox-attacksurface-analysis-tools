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

using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    public enum NlsSectionType
    {
        CodePage = 11,
        Normalization = 12,
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtGetNlsSectionPtr(NlsSectionType NlsType, int CodePage, IntPtr ContextData, out IntPtr SectionPointer, out IntPtr SectionSize);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetDefaultLocale(bool ThreadOrSystem, uint Locale);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryDefaultLocale(bool ThreadOrSystem, out uint Locale);
    }

    public static class NtLocale
    {
        public static NtMappedSection GetNlsSectionPtr(NlsSectionType type, int codepage)
        {
            IntPtr ptr;
            IntPtr size;
            NtObject.StatusToNtException(NtSystemCalls.NtGetNlsSectionPtr(type, codepage, IntPtr.Zero, out ptr, out size));
            return new NtMappedSection(ptr, size.ToInt64(), NtProcess.Current, false);
        }

        public static uint GetDefaultLocal(bool thread)
        {
            uint locale;
            NtObject.StatusToNtException(NtSystemCalls.NtQueryDefaultLocale(thread, out locale));
            return locale;
        }

        public static void SetDefaultLocale(bool thread, uint locale)
        {
            NtObject.StatusToNtException(NtSystemCalls.NtSetDefaultLocale(thread, locale));
        }
    }
}
