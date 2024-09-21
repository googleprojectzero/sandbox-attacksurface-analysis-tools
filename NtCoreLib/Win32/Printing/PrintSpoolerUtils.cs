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

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Win32.Printing.Interop;
using System.Collections.Generic;
using System.Linq;

namespace NtCoreLib.Win32.Printing;

/// <summary>
/// Utils for print spooler.
/// </summary>
public static class PrintSpoolerUtils
{
    /// <summary>
    /// Name for the fake printer NT type.
    /// </summary>
    public const string PRINTER_NT_TYPE_NAME = "Printer";

    /// <summary>
    /// Name for the fake print server NT type.
    /// </summary>
    public const string PRINT_SERVER_NT_TYPE_NAME = "PrintServer";

    /// <summary>
    /// Name for the fake print server NT type.
    /// </summary>
    public const string PRINT_JOB_NT_TYPE_NAME = "PrintJob";

    /// <summary>
    /// Get the generic mapping for printer objects.
    /// </summary>
    /// <returns>The printer objects generic mapping.</returns>
    public static GenericMapping PrinterGenericMapping => new GenericMapping
    {
        GenericRead = PrintSpoolerAccessRights.PrinterUse | PrintSpoolerAccessRights.ReadControl,
        GenericWrite = PrintSpoolerAccessRights.PrinterUse | PrintSpoolerAccessRights.ReadControl,
        GenericExecute = PrintSpoolerAccessRights.PrinterUse | PrintSpoolerAccessRights.ReadControl,
        GenericAll = PrintSpoolerAccessRights.WriteOwner | PrintSpoolerAccessRights.WriteDac | PrintSpoolerAccessRights.ReadControl | PrintSpoolerAccessRights.Delete |
                    PrintSpoolerAccessRights.PrinterUse | PrintSpoolerAccessRights.PrinterAdminister
    };

    /// <summary>
    /// Get the generic mapping for job objects.
    /// </summary>
    /// <returns>The job objects generic mapping.</returns>
    public static GenericMapping PrintJobGenericMapping => new GenericMapping
    {
        GenericRead = PrintSpoolerAccessRights.JobRead | PrintSpoolerAccessRights.ReadControl,
        GenericWrite = PrintSpoolerAccessRights.JobAdminister | PrintSpoolerAccessRights.ReadControl,
        GenericExecute = PrintSpoolerAccessRights.JobAdminister | PrintSpoolerAccessRights.ReadControl,
        GenericAll = PrintSpoolerAccessRights.WriteOwner | PrintSpoolerAccessRights.WriteDac | PrintSpoolerAccessRights.ReadControl | PrintSpoolerAccessRights.Delete |
                    PrintSpoolerAccessRights.JobRead | PrintSpoolerAccessRights.JobAdminister
    };

    /// <summary>
    /// Get the generic mapping for server objects.
    /// </summary>
    /// <returns>The server objects generic mapping.</returns>
    public static GenericMapping PrintServerGenericMapping => new GenericMapping
    {
        GenericRead = PrintSpoolerAccessRights.ServerEnumerate | PrintSpoolerAccessRights.ReadControl,
        GenericWrite = PrintSpoolerAccessRights.ServerEnumerate | PrintSpoolerAccessRights.ServerAdminister | PrintSpoolerAccessRights.ReadControl,
        GenericExecute = PrintSpoolerAccessRights.ServerEnumerate | PrintSpoolerAccessRights.ReadControl,
        GenericAll = PrintSpoolerAccessRights.WriteOwner | PrintSpoolerAccessRights.WriteDac |
                    PrintSpoolerAccessRights.ReadControl | PrintSpoolerAccessRights.Delete |
                    PrintSpoolerAccessRights.ServerAdminister | PrintSpoolerAccessRights.ServerEnumerate
    };

    /// <summary>
    /// Get the appropriate NT type for the printer path.
    /// </summary>
    /// <param name="path">The printer path, e.g. \\server\printer.</param>
    /// <returns>The NT type.</returns>
    public static NtType GetTypeForPath(string path)
    {
        return NtType.GetTypeByName(IsPrintServer(path) ? PRINT_SERVER_NT_TYPE_NAME : PRINTER_NT_TYPE_NAME);
    }

    /// <summary>
    /// Enumerate local printers.
    /// </summary>
    /// <returns>The list of local printers.</returns>
    public static IReadOnlyList<LocalPrinter> EnumerateLocalPrinters()
    {
        const int PRINTER_ENUM_LOCAL = 0x00000002;

        List<LocalPrinter> ret = new();

        NativeMethods.EnumPrinters(PRINTER_ENUM_LOCAL, null, 4, SafeHGlobalBuffer.Null, 0, out int length_needed, out int length_returned);
        if (length_needed == 0)
        {
            return ret.AsReadOnly();
        }

        using var buffer = new SafeHGlobalBuffer(length_needed);
        NativeMethods.EnumPrinters(PRINTER_ENUM_LOCAL, null, 4, buffer, buffer.Length, out length_needed, out length_returned).ToNtException(true);
        PRINTER_INFO_4[] printer_infos = buffer.ReadArray<PRINTER_INFO_4>(0, length_returned);
        ret.AddRange(printer_infos.Select(i => new LocalPrinter(i)));
        return ret.AsReadOnly();
    }

    private static bool IsPrintServer(string path)
    {
        if (string.IsNullOrEmpty(path))
            return true;
        path = path.Replace('/', '\\');
        if (!path.StartsWith("\\\\"))
            return false;
        return path.LastIndexOf('\\') == 1;
    }
}
