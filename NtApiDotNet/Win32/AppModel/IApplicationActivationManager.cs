//  Copyright 2020 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet.Win32.AppModel
{
    internal enum ACTIVATEOPTIONS
    {
        AO_NONE = 0x00000000,  // No flags set
        AO_DESIGNMODE = 0x00000001,  // The application is being activated for design mode, and thus will not be able to
                                     // to create an immersive window. Window creation must be done by design tools which
                                     // load the necessary components by communicating with a designer-specified service on
                                     // the site chain established on the activation manager.  The splash screen normally
                                     // shown when an application is activated will also not appear.  Most activations
                                     // will not use this flag.
        AO_NOERRORUI = 0x00000002,  // Do not show an error dialog if the app fails to activate.
        AO_NOSPLASHSCREEN = 0x00000004,  // Do not show the splash screen when activating the app.
        AO_PRELAUNCH = 0x02000000,  // The application is being activated in Prelaunch mode.
    }

    [Guid("2e941141-7f97-4756-ba1d-9decde894a3d")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    [ComImport]
    internal interface IApplicationActivationManager
    {
        [PreserveSig]
        NtStatus ActivateApplication(
            string appUserModelId,
            string arguments,
            ACTIVATEOPTIONS options,
            out int processId);

        [PreserveSig]
        NtStatus ActivateForFile(
            string appUserModelId,
            IntPtr itemArray, // IShellItemArray
            string verb,
            out int processId);

        [PreserveSig]
        NtStatus ActivateForProtocol(
            string appUserModelId,
            IntPtr itemArray, // IShellItemArray
            out int processId);
    }

    [Guid("45BA127D-10A8-46EA-8AB7-56EA9078943C")]
    [ComImport]
    class ApplicationActivationManager
    {
    }
}
