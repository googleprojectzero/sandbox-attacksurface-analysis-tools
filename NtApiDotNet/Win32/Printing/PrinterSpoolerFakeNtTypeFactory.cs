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

using System.Collections.Generic;

namespace NtApiDotNet.Win32.Printing
{
    internal class PrinterSpoolerFakeNtTypeFactory : NtFakeTypeFactory
    {
        public override IEnumerable<NtType> CreateTypes()
        {
            return new NtType[] { new NtType(PrintSpoolerUtils.PRINTER_NT_TYPE_NAME, PrintSpoolerUtils.PrinterGenericMapping,
                        typeof(PrintSpoolerAccessRights), typeof(PrintSpoolerAccessRights),
                        MandatoryLabelPolicy.NoWriteUp),
                        new NtType(PrintSpoolerUtils.PRINT_SERVER_NT_TYPE_NAME, PrintSpoolerUtils.PrintServerGenericMapping,
                        typeof(PrintSpoolerAccessRights), typeof(PrintSpoolerAccessRights),
                        MandatoryLabelPolicy.NoWriteUp),
                        new NtType(PrintSpoolerUtils.PRINT_JOB_NT_TYPE_NAME, PrintSpoolerUtils.PrintJobGenericMapping,
                        typeof(PrintSpoolerAccessRights), typeof(PrintSpoolerAccessRights),
                        MandatoryLabelPolicy.NoWriteUp)
            };
        }
    }
}
