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

namespace NtApiDotNet
{
    /// <summary>
    /// Access rights for ALPC
    /// </summary>
#pragma warning disable 1591
    [Flags]
    public enum AlpcAccessRights : uint
    {
        Connect = 0x1,
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

    /// <summary>
    /// ALPC Port Information Class
    /// </summary>
    public enum AlpcPortInformationClass
    {
        AlpcBasicInformation, 
        AlpcPortInformation,
        AlpcAssociateCompletionPortInformation, 
        AlpcConnectedSIDInformation, 
        AlpcServerInformation, 
        AlpcMessageZoneInformation, 
        AlpcRegisterCompletionListInformation, 
        AlpcUnregisterCompletionListInformation,
        AlpcAdjustCompletionListConcurrencyCountInformation,
        AlpcRegisterCallbackInformation,
        AlpcCompletionListRundownInformation,
        AlpcWaitForPortReferences
    }

    public class AlpcPortMessage
    {
        [StructLayout(LayoutKind.Explicit)]
        public struct PortMessageUnion1
        {
            [FieldOffset(0)]
            public ushort DataLength;
            [FieldOffset(2)]
            public ushort TotalLength;
            [FieldOffset(0)]
            public uint Length;
        }
        public PortMessageUnion1 u1;

        [StructLayout(LayoutKind.Explicit)]
        public struct PortMessageUnion2
        {
            [FieldOffset(0)]
            public ushort Type;
            [FieldOffset(2)]
            public ushort DataInfoOffset;
            [FieldOffset(0)]
            public uint ZeroInit;
        }
        public PortMessageUnion2 u2;

        public ClientIdStruct ClientId;
        public uint MessageId;

        [StructLayout(LayoutKind.Explicit)]
        public struct PortMessageUnion3
        {
            [FieldOffset(0)]
            public IntPtr ClientViewSize;
            [FieldOffset(0)]
            public uint CallbackId;
        }
        public PortMessageUnion3 u3;
    }

    [StructLayout(LayoutKind.Sequential)]
    public class AlpcPortAttributes
    {
        public uint Flags;
        SecurityQualityOfServiceStruct SecurityQos;
        IntPtr MaxMessageLength;
        IntPtr MemoryBandwidth;
        IntPtr MaxPoolUsage;
        IntPtr MaxSectionSize;
        IntPtr MaxViewSize;
        IntPtr MaxTotalSectionSize;
        uint DupObjectTypes;
        uint Reserved; // Only Win64?
    }

    [StructLayout(LayoutKind.Sequential)]
    public class AlpcMessageAtributes
    {
        public uint AllocatedAttributes;
        public uint ValidAttributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public class AlpcContextAttr
    {
        public IntPtr PortContext;
        public IntPtr MessageContext;
        public uint Sequence;
        public uint MessageId;
        public uint CallbackId;
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcCreatePort(
            out SafeKernelObjectHandle PortHandle,
            [In] ObjectAttributes ObjectAttributes,
            AlpcPortAttributes PortAttributes
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcDisconnectPort(
            [In] SafeKernelObjectHandle PortHandle,
            uint Flags
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcQueryInformation(
            SafeKernelObjectHandle PortHandle,
            AlpcPortInformationClass PortInformationClass,
            IntPtr PortInformation,
            int Length,
            out int ReturnLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcSetInformation(
            [In] SafeKernelObjectHandle PortHandle,
            AlpcPortInformationClass PortInformationClass,
            IntPtr PortInformation,
            int Length);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcConnectPort(
            out SafeKernelObjectHandle PortHandle,
            [In] UnicodeString PortName,
            [Optional, In] ObjectAttributes ObjectAttributes,
            [Optional, In] AlpcPortAttributes PortAttributes,
            uint Flags,
            [Optional] IntPtr RequiredServerSid,
            [Optional, In, Out] AlpcPortMessage ConnectionMessage,
            [Optional, In, Out] OptionalInt32 BufferLength,
            [Optional, In, Out] AlpcMessageAtributes OutMessageAttributes,
            [Optional, In, Out] AlpcMessageAtributes InMessageAttributes,
            [Optional, In] LargeInteger Timeout
        );

        [DllImport("ntdll.dll")]
        [SupportedVersion(SupportedVersion.Windows8)]
        public static extern NtStatus NtAlpcConnectPortEx(
            out SafeKernelObjectHandle PortHandle,
            [In] ObjectAttributes ConnectionPortObjectAttributes,
            [Optional, In] ObjectAttributes ClientPortObjectAttributes,
            [Optional, In] AlpcPortAttributes PortAttributes,
            uint Flags,
            [Optional] IntPtr ServerSecurityRequirements, // SECURITY_DESCRIPTOR
            [Optional, In, Out] AlpcPortMessage ConnectionMessage,
            [Optional, In, Out] OptionalLength BufferLength,
            [Optional, In, Out] AlpcMessageAtributes OutMessageAttributes,
            [Optional, In, Out] AlpcMessageAtributes InMessageAttributes,
            [Optional, In] LargeInteger Timeout);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcSendWaitReceivePort(
            [In] SafeKernelObjectHandle PortHandle,
            uint Flags,
            [Optional, In] AlpcPortMessage SendMessage,
            [Optional, In, Out] AlpcMessageAtributes SendMessageAttributes,
            [Optional, Out] AlpcPortMessage ReceiveMessage,
            [Optional, In, Out] OptionalLength BufferLength,
            [Optional, In, Out] AlpcMessageAtributes ReceiveMessageAttributes,
            [Optional, In] LargeInteger Timeout);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcCancelMessage(
            [In] SafeKernelObjectHandle PortHandle,
            uint Flags,
            [In] AlpcContextAttr MessageContext
           );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcImpersonateClientOfPort(
                [In] SafeKernelObjectHandle PortHandle,
                [In] AlpcPortMessage PortMessage,
                uint Flags
        );
        
        [DllImport("ntdll.dll")]
        [SupportedVersion(SupportedVersion.Windows10_TH2)]
        public static extern NtStatus NtAlpcImpersonateClientContainerOfPort(
            [In] SafeKernelObjectHandle PortHandle,
            [In] AlpcPortMessage PortMessage,
            uint Flags
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcOpenSenderProcess(
            out SafeKernelObjectHandle ProcessHandle,
            [In] SafeKernelObjectHandle PortHandle,
            [In] AlpcPortMessage PortMessage,
            uint Flags,
            ProcessAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcOpenSenderThread(
            out SafeKernelObjectHandle ThreadHandle,
            [In] SafeKernelObjectHandle PortHandle,
            [In] AlpcPortMessage PortMessage,
            uint Flags,
            ProcessAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes);
    }
#pragma warning restore 1591

    /// <summary>
    /// Unused.
    /// </summary>
    public class NtAlpc : NtObjectWithDuplicate<NtAlpc, AlpcAccessRights>
    {
        internal NtAlpc(SafeKernelObjectHandle handle) : base(handle)
        {
        }
    }
}
