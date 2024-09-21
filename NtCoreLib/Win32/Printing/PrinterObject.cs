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

namespace NtApiDotNet.Win32.Printing
{
    /// <summary>
    /// Class to represent a printer object.
    /// </summary>
    public sealed class PrinterObject : IDisposable
    {
        private readonly IntPtr _handle;
        private readonly string _path;
        private readonly NtType _type;

        private PrinterObject(IntPtr handle, string path)
        {
            _handle = handle;
            _path = path;
            _type = PrintSpoolerUtils.GetTypeForPath(path);
        }

        /// <summary>
        /// Dispose the printer object.
        /// </summary>
        public void Dispose()
        {
            if (_handle != IntPtr.Zero)
            {
                PrintingNativeMethods.ClosePrinter(_handle);
            }
        }

        /// <summary>
        /// Open a printer or server.
        /// </summary>
        /// <param name="printer_name">The name of the printer or server. If this is null or empty then it's the local server.</param>
        /// <param name="desired_access">The desired access on the printer.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened printer.</returns>
        public static NtResult<PrinterObject> OpenPrinter(string printer_name, PrintSpoolerAccessRights desired_access, bool throw_on_error)
        {
            PRINTER_DEFAULTS defs = new PRINTER_DEFAULTS();
            defs.DesiredAccess = desired_access;
            return PrintingNativeMethods.OpenPrinter(printer_name, out IntPtr handle, defs).CreateWin32Result(throw_on_error, () => new PrinterObject(handle, printer_name));
        }

        /// <summary>
        /// Open a printer.
        /// </summary>
        /// <param name="printer_name">The name of the printer.</param>
        /// <param name="desired_access">The desired access on the printer.</param>
        /// <returns>The opened printer.</returns>
        public static PrinterObject OpenPrinter(string printer_name, PrintSpoolerAccessRights desired_access)
        {
            return OpenPrinter(printer_name, desired_access, true).Result;
        }

        /// <summary>
        /// Open a printer.
        /// </summary>
        /// <param name="printer_name">The name of the printer.</param>
        /// <returns>The opened printer.</returns>
        public static PrinterObject OpenPrinter(string printer_name)
        {
            return OpenPrinter(printer_name, PrintSpoolerAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Get security descriptor for the printer.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The printer's security descriptor.</returns>
        public NtResult<SecurityDescriptor> GetSecurityDescriptor(bool throw_on_error)
        {
            PrintingNativeMethods.GetPrinter(_handle, 3, SafeHGlobalBuffer.Null, 0, out int length);
            using (var buffer = new SafeStructureInOutBuffer<PRINTER_INFO_3>(length, false))
            {
                var error = PrintingNativeMethods.GetPrinter(_handle, 3, buffer, length, out length).GetLastWin32Error();
                if (error != Win32Error.SUCCESS)
                {
                    return error.CreateResultFromDosError<SecurityDescriptor>(throw_on_error);
                }

                return SecurityDescriptor.Parse(buffer.Result.pSecurityDescriptor, _type, throw_on_error);
            }
        }

        /// <summary>
        /// Get security descriptor for the printer.
        /// </summary>
        /// <returns>The printer's security descriptor.</returns>
        public SecurityDescriptor GetSecurityDescriptor()
        {
            return GetSecurityDescriptor(true).Result;
        }
    }
}
