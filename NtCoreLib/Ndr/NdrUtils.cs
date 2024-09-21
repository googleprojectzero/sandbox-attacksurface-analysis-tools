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

using System.Diagnostics;

namespace NtCoreLib.Ndr;

/// <summary>
/// Utilities for NDR marshaling.
/// </summary>
public static class NdrUtils
{
    internal static TraceSwitch NdrMarshalTraceSwitch = new("NdrMarshalTrace", "NDR Marshal Tracing");

    /// <summary>
    /// Specify NDR marshaler trace level.
    /// </summary>
    /// <param name="level">Specify the NDR marshaler trace level.</param>
    /// <remarks>Verbose marshal stack details.</remarks>
    public static void SetNdrMarshalTraceLevel(TraceLevel level)
    {
        NdrMarshalTraceSwitch.Level = level;
    }

    internal static void WriteLine(string message)
    {
        if (NdrMarshalTraceSwitch.TraceVerbose)
        {
            Trace.WriteLine(message);
        }
    }
}
