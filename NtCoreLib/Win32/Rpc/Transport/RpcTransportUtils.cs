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

using NtCoreLib.Kernel.Alpc;
using NtCoreLib.Utilities.Text;
using System;
using System.Diagnostics;

namespace NtCoreLib.Win32.Rpc.Transport;

/// <summary>
/// Static utilities for the RPC transport.
/// </summary>
public static class RpcTransportUtils
{
    /// <summary>
    /// Specify global RPC trace flags
    /// </summary>
    public static RpcTransportTraceFlags GlobalTraceFlags { get; set; }

    /// <summary>
    /// Specify the function for RPC transport tracing. If not set will output to the .NET Trace class.
    /// </summary>
    public static Action<string, byte[]> TraceFunc { get; set; }

    private static void OutputTrace(string title, byte[] buffer)
    {
        Trace.WriteLine($"{title}:");
        Trace.WriteLine(HexDumpBuilder.ToHexDump(buffer, true, true, true, true));
    }

    private static void DumpBuffer(RpcTransportTraceFlags curr_flags, RpcTransportTraceFlags req_flags, string title, Func<byte[]> func)
    {
        curr_flags |= GlobalTraceFlags;
        if ((curr_flags & req_flags) == RpcTransportTraceFlags.None)
            return;
        (TraceFunc ?? OutputTrace)(title, func());
    }

    internal static void DumpBuffer(RpcTransportTraceFlags curr_flags, RpcTransportTraceFlags req_flags, string title, byte[] buffer)
    {
        DumpBuffer(curr_flags, req_flags, title, () => buffer);
    }

    internal static void DumpBuffer(RpcTransportTraceFlags curr_flags, RpcTransportTraceFlags req_flags, string title, AlpcMessage message)
    {
        DumpBuffer(curr_flags, req_flags, title, () =>
        {
            using var buffer = message.ToSafeBuffer();
            return buffer.ToArray();
        });
    }
}