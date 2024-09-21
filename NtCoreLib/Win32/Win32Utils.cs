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

using System;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32;

internal static class Win32Utils
{
    internal static Win32Error GetLastWin32Error() => (Win32Error)Marshal.GetLastWin32Error();

    internal static Win32Error GetLastWin32Error(this bool result) => result ? Win32Error.SUCCESS : GetLastWin32Error();

    internal static void ToNtException(this Win32Error dos_error) => ToNtException(dos_error, true);

    internal static NtStatus ToNtException(this Win32Error dos_error, bool throw_on_error)
    {
        return dos_error.MapDosErrorToStatus().ToNtException(throw_on_error);
    }

    internal static NtStatus ToNtException(this bool result, bool throw_on_error)
    {
        return GetLastWin32Error(result).ToNtException(throw_on_error);
    }

    internal static NtResult<T> CreateWin32Result<T>(this bool result, bool throw_on_error, Func<T> create_func)
    {
        return result ? create_func().CreateResult() : CreateResultFromDosError<T>(throw_on_error);
    }

    internal static NtResult<T> CreateWin32Result<T>(this Win32Error result, bool throw_on_error, Func<T> create_func)
    {
        return result == Win32Error.SUCCESS ? create_func().CreateResult() : result.CreateResultFromDosError<T>(throw_on_error);
    }

    internal static NtResult<T> CreateWin32Result<T, H>(this H result, bool throw_on_error, Func<H, T> create_func) where H : SafeHandle
    {
        return !result.IsInvalid ? create_func(result).CreateResult() : CreateResultFromDosError<T>(throw_on_error);
    }

    internal static NtResult<T> CreateResultFromDosError<T>(this Win32Error error, bool throw_on_error)
    {
        NtStatus status = error.MapDosErrorToStatus();
        if (throw_on_error)
        {
            throw new NtException(status);
        }

        return new NtResult<T>(status, default);
    }

    internal static NtResult<T> CreateResultFromDosError<T>(bool throw_on_error)
    {
        return GetLastWin32Error().CreateResultFromDosError<T>(throw_on_error);
    }

    internal static NtStatus ToHresult(this Win32Error error)
    {
        return NtObjectUtils.BuildStatus(NtStatusSeverity.STATUS_SEVERITY_WARNING, false, false, NtStatusFacility.FACILITY_NTWIN32, (int)error);
    }
}
