//  Copyright 2018 Google Inc. All Rights Reserved.
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
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace NtCoreLib.Win32.Tracing.Interop;

[StructLayout(LayoutKind.Sequential)]
internal struct EVENT_TRACE_PROPERTIES
{
    public WNODE_HEADER Wnode;
    public int BufferSize;
    public int MinimumBuffers;
    public int MaximumBuffers;
    public int MaximumFileSize;
    public LogFileModeFlags LogFileMode;
    public int FlushTimer;
    public int EnableFlags;
    public int AgeLimit;
    public int NumberOfBuffers;
    public int FreeBuffers;
    public int EventsLost;
    public int BuffersWritten;
    public int LogBuffersLost;
    public int RealTimeBuffersLost;
    public IntPtr LoggerThreadId;
    public int LogFileNameOffset;
    public int LoggerNameOffset;

    public SafeHGlobalBuffer ToBuffer(string log_file, string logger_name)
    {
        MemoryStream stm = new();
        BinaryWriter writer = new(stm);

        if (logger_name != null)
        {
            writer.Write(Encoding.Unicode.GetBytes(logger_name + "\0"));
        }
        else
        {
            stm.Position += 1024;
        }

        int file_offset = (int)stm.Position;

        if (log_file != null)
        {
            writer.Write(Encoding.Unicode.GetBytes(log_file + "\0"));
        }
        else
        {
            stm.Position = 1024;
        }

        byte[] data = stm.ToArray();

        int total_size = Marshal.SizeOf(typeof(EVENT_TRACE_PROPERTIES)) + data.Length;
        Wnode.BufferSize = total_size;
        LoggerNameOffset = Marshal.SizeOf(typeof(EVENT_TRACE_PROPERTIES));
        LogFileNameOffset = LoggerNameOffset + file_offset;

        using var buffer = this.ToBuffer(data.Length, true);
        buffer.Data.WriteBytes(stm.ToArray());
        return buffer.Detach();
    }
}
#pragma warning restore 1591
