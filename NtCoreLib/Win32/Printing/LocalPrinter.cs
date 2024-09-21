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

using NtCoreLib.Win32.Printing.Interop;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Printing;

/// <summary>
/// Local printer information.
/// </summary>
public sealed class LocalPrinter
{
    /// <summary>
    /// The name of the printer.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// The printer's server name.
    /// </summary>
    public string ServerName { get; }

    /// <summary>
    /// The printer's attributes.
    /// </summary>
    public PrinterAttributes Attributes { get; }

    internal LocalPrinter(PRINTER_INFO_4 printer_info)
    {
        Name = Marshal.PtrToStringUni(printer_info.pPrinterName);
        ServerName = Marshal.PtrToStringUni(printer_info.pServerName);
        Attributes = printer_info.Attributes;
    }
}
