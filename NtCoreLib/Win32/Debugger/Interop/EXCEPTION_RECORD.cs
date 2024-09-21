//  Copyright 2019 Google Inc. All Rights Reserved.
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

namespace NtCoreLib.Win32.Debugger.Interop;

[StructLayout(LayoutKind.Sequential)]
internal struct EXCEPTION_RECORD
{
    public int ExceptionCode;
    public int ExceptionFlags;
    public IntPtr ExceptionRecordChain;
    public IntPtr ExceptionAddress;
    public int NumberParameters;
    public IntPtr ExceptionInformation0;
    public IntPtr ExceptionInformation1;
    public IntPtr ExceptionInformation2;
    public IntPtr ExceptionInformation3;
    public IntPtr ExceptionInformation4;
    public IntPtr ExceptionInformation5;
    public IntPtr ExceptionInformation6;
    public IntPtr ExceptionInformation7;
    public IntPtr ExceptionInformation8;
    public IntPtr ExceptionInformation9;
    public IntPtr ExceptionInformationA;
    public IntPtr ExceptionInformationB;
    public IntPtr ExceptionInformationC;
    public IntPtr ExceptionInformationD;
    public IntPtr ExceptionInformationE;
}


