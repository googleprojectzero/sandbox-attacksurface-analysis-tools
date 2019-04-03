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

using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    [Flags]
    public enum IoCompletionAccessRights : uint
    {
        QueryState = 1,
        SetCompletion = 2,
        GenericRead = GenericAccessRights.GenericRead,
        GenericWrite = GenericAccessRights.GenericWrite,
        GenericExecute = GenericAccessRights.GenericExecute,
        GenericAll = GenericAccessRights.GenericAll,
        Delete = GenericAccessRights.Delete,
        ReadControl = GenericAccessRights.ReadControl,
        WriteDac = GenericAccessRights.WriteDac,
        WriteOwner = GenericAccessRights.WriteOwner,
        Synchronize = GenericAccessRights.Synchronize,
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
        AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
    }

    public enum IoCompletionInformationClass
    {
        IoCompletionBasicInformation
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileIoCompletionInformation
    {
        public IntPtr KeyContext;
        public IntPtr ApcContext;
        public IoStatusStruct IoStatusBlock;
    }

    public class FileIoCompletionResult
    {
        public IntPtr KeyContext { get; }
        public IntPtr ApcContext { get; }
        public IoStatus IoStatusBlock { get; }

        internal FileIoCompletionResult(FileIoCompletionInformation result)
        {
            KeyContext = result.KeyContext;
            ApcContext = result.ApcContext;
            IoStatusBlock = new IoStatus()
            {
                Information = result.IoStatusBlock.Information,
                Pointer = result.IoStatusBlock.Pointer
            };
        }

        internal FileIoCompletionResult(IntPtr key_context, IntPtr apc_context, IoStatus io_status)
        {
            KeyContext = key_context;
            ApcContext = apc_context;
            IoStatusBlock = io_status;
        }

    }

    public struct IoCompletionBasicInformation
    {
        public int Depth;
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtCreateIoCompletion(
            out SafeKernelObjectHandle IoCompletionHandle,
            IoCompletionAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes,
            int NumberOfConcurrentThreads
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtOpenIoCompletion(
            out SafeKernelObjectHandle IoCompletionHandle,
            IoCompletionAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRemoveIoCompletion(
            SafeKernelObjectHandle IoCompletionHandle,
            out IntPtr KeyContext,
            out IntPtr ApcContext,
            [In, Out] IoStatus IoStatusBlock,
            LargeInteger Timeout
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtRemoveIoCompletionEx(
            SafeKernelObjectHandle IoCompletionHandle,
            [Out] FileIoCompletionInformation[] IoCompletionInformation,
            int InformationCount,
            out int NumEntriesRemoved,
            [In] LargeInteger Timeout,
            bool Alertable
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtQueryIoCompletion(
            SafeKernelObjectHandle IoCompletionHandle,
            IoCompletionInformationClass IoCompletionInformationClass,
            SafeBuffer IoCompletionInformation,
            int IoCompletionInformationLength,
            out int ReturnLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetIoCompletion(
            SafeKernelObjectHandle IoCompletionHandle,
            IntPtr KeyContext,
            IntPtr ApcContext,
            NtStatus Status,
            IntPtr IoStatusInformation
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSetIoCompletionEx(
            SafeKernelObjectHandle IoCompletionHandle,
            SafeKernelObjectHandle IoCompletionPacketHandle,
            IntPtr KeyContext,
            IntPtr ApcContext,
            NtStatus IoStatus,
            IntPtr IoStatusInformation
        );
    }

#pragma warning restore 1591
}
