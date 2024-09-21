//  Copyright 2021 Google LLC. All Rights Reserved.
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

namespace NtApiDotNet.Win32.Printing
{
    [StructLayout(LayoutKind.Sequential)]
    internal class PRINTER_DEFAULTS
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pDatatype;
        public IntPtr pDevMode; // LPDEVMODE
        public PrintSpoolerAccessRights DesiredAccess;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PRINTER_INFO_3
    {
        public IntPtr pSecurityDescriptor;
    }

    internal static class PrintingNativeMethods
    {
        [DllImport("Winspool.drv", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool OpenPrinter(
            string pPrinterName,
            out IntPtr phPrinter,
            PRINTER_DEFAULTS pDefault
        );

        [DllImport("Winspool.drv", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool GetPrinter(
          IntPtr hPrinter,
          int Level,
          SafeBuffer pPrinter,
          int cbBuf,
          out int pcbNeeded
        );

        [DllImport("Winspool.drv", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool ClosePrinter(
            IntPtr hPrinter
        );
    }
}
