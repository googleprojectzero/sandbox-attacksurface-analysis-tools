//  Copyright 2016, 2017 Google Inc. All Rights Reserved.
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

using NtCoreLib.Win32.Service.Interop;

#nullable enable

namespace NtCoreLib.Win32.Service;

/// <summary>
/// Structure to represent the service process status.
/// </summary>
public readonly struct ServiceStatusProcess
{
    #region Public Properties
    /// <summary>
    /// The type of service.
    /// </summary>
    public ServiceType ServiceType { get; }

    /// <summary>
    /// The current service status.
    /// </summary>
    public ServiceStatus CurrentState { get; }

    /// <summary>
    /// Controls accepted by the service.
    /// </summary>
    public ServiceControlsAccepted ControlsAccepted { get; }

    /// <summary>
    /// The Win32 exit code.
    /// </summary>
    public Win32Error Win32ExitCode { get; }

    /// <summary>
    /// Service specific error code.
    /// </summary>
    public int ServiceSpecificExitCode { get; }

    /// <summary>
    /// Check point value.
    /// </summary>
    public int CheckPoint { get; }

    /// <summary>
    /// Wait hint.
    /// </summary>
    public int WaitHint { get; }

    /// <summary>
    /// The current process ID.
    /// </summary>
    public int ProcessId { get; }

    /// <summary>
    /// Service flags.
    /// </summary>
    public ServiceFlags ServiceFlags { get; }
    #endregion

    #region Internal Members
    internal ServiceStatusProcess(SERVICE_STATUS_PROCESS status)
    {
        ServiceType = status.dwServiceType;
        CurrentState = status.dwCurrentState;
        ControlsAccepted = status.dwControlsAccepted;
        Win32ExitCode = status.dwWin32ExitCode;
        ServiceSpecificExitCode = status.dwServiceSpecificExitCode;
        CheckPoint = status.dwCheckPoint;
        WaitHint = status.dwWaitHint;
        ProcessId = status.dwProcessId;
        ServiceFlags = status.dwServiceFlags;
    }

    internal ServiceStatusProcess(SERVICE_STATUS status)
    {
        ServiceType = status.dwServiceType;
        CurrentState = status.dwCurrentState;
        ControlsAccepted = status.dwControlsAccepted;
        Win32ExitCode = status.dwWin32ExitCode;
        ServiceSpecificExitCode = status.dwServiceSpecificExitCode;
        CheckPoint = status.dwCheckPoint;
        WaitHint = status.dwWaitHint;
        ProcessId = 0;
        ServiceFlags = 0;
    }
    #endregion
}
