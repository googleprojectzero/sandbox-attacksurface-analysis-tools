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

    public enum AlpcMessageInformationClass
    {
        AlpcMessageSidInformation = 0,
        AlpcMessageTokenModifiedIdInformation,
        AlpcMessageDirectStatusInformation,
        AlpcMessageHandleInformation,
    }

    [StructLayout(LayoutKind.Sequential)]
    public class AlpcPortMessage
    {
        [StructLayout(LayoutKind.Explicit)]
        public struct PortMessageUnion1
        {
            [FieldOffset(0)]
            public short DataLength;
            [FieldOffset(2)]
            public short TotalLength;
            [FieldOffset(0)]
            public uint Length;
        }
        public PortMessageUnion1 u1;

        [StructLayout(LayoutKind.Explicit)]
        public struct PortMessageUnion2
        {
            [FieldOffset(0)]
            public short Type;
            [FieldOffset(2)]
            public short DataInfoOffset;
            [FieldOffset(0)]
            public uint ZeroInit;
        }
        public PortMessageUnion2 u2;

        public ClientIdStruct ClientId;
        public int MessageId;

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

    

    [Flags]
    public enum AlpcPortAttributeFlags
    {
        None = 0,
        LpcPort = 0x1000, // Not accessible outside the kernel.
        Unknown10000 = 0x10000,
        AllowLpcRequests = 0x20000,
        WaitablePort = 0x40000,
        Unknown80000 = 0x80000,
        SystemProcess = 0x100000 // Not accessible outside the kernel.
    }

    [StructLayout(LayoutKind.Sequential)]
    public class AlpcPortAttributes
    {
        public AlpcPortAttributeFlags Flags;
        public SecurityQualityOfServiceStruct SecurityQos;
        public IntPtr MaxMessageLength;
        public IntPtr MemoryBandwidth;
        public IntPtr MaxPoolUsage;
        public IntPtr MaxSectionSize;
        public IntPtr MaxViewSize;
        public IntPtr MaxTotalSectionSize;
        public uint DupObjectTypes;
        public uint Reserved; // Only Win64?
    }

    [Flags]
    public enum AlpcSecurityAttributeFlags
    {
        None = 0,
        CreateHandle = 0x20000,
    }

    [StructLayout(LayoutKind.Sequential)]
    public class AlpcSecurityAttribute
    {
        public AlpcSecurityAttributeFlags Flags;
        public IntPtr QoS;
        public IntPtr ContextHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public class AlpcContextAttribute
    {
        public IntPtr PortContext;
        public IntPtr MessageContext;
        public uint Sequence;
        public uint MessageId;
        public uint CallbackId;
    }

    [Flags]
    public enum AlpcMessageAttributeFlags : uint
    {
        None = 0,
        WorkOnBehalfOf = 0x2000000,
        Direct = 0x4000000,
        Token = 0x8000000,
        Handle = 0x10000000,
        Context = 0x20000000,
        View = 0x40000000,
        Security = 0x80000000,
    }

    public enum AlpcSecurityAttrFlags
    {
        None = 0,
        CreateHandle = 0x20000
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AlpcSecurityAttr
    {
        public AlpcSecurityAttrFlags Flags;
        public IntPtr QoS; // struct _SECURITY_QUALITY_OF_SERVICE
        public IntPtr ContextHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AlpcContextAttr
    {
        public IntPtr PortContext;
        public IntPtr MessageContext;
        public int Sequence;
        public int MessageId;
        public int CallbackId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AlpcDirectAttr
    {
        public IntPtr Event;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AlpcWorkOnBehalfTicket
    {
        public int ThreadId;
        public int ThreadCreationTimeLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AlpcWorkOnBehalfAttr
    {
        public AlpcWorkOnBehalfTicket Ticket;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AlpcTokenAttr
    {
        public Luid TokenId;
        public Luid AuthenticationId;
        public Luid ModifiedId;
    }

    [Flags]
    public enum AlpcHandleAttrFlags
    {
        None = 0,
        SameAccess = 0x10000,
        SameAttributes = 0x20000,
        Indirect = 0x40000,
        Inherit = 0x80000
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AlpcHandleAttr
    {
        public AlpcHandleAttrFlags Flags;
        public IntPtr Handle; // Also ALPC_HANDLE_ATTR32* HandleAttrArray;
        public int ObjectType; // Also HandleCount;
        public AccessMask DesiredAccess; // Also GrantedAccess
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AlpcHandleAttr32
    {
        public AlpcHandleAttrFlags Flags;
        public int Handle;
        public int ObjectType;
        public AccessMask DesiredAccess;
    }

    [Flags]
    public enum AlpcDataViewAttrFlags
    {
        None = 0,
        NotSecure = 0x40000
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AlpcDataViewAttr
    {
        public AlpcDataViewAttrFlags Flags;
        public IntPtr SectionHandle;            // ALPC_HANDLE.
        public IntPtr ViewBase;
        public long ViewSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AlpcMessageAttributes
    {
        public AlpcMessageAttributeFlags AllocatedAttributes;
        public AlpcMessageAttributeFlags ValidAttributes;
    }

    [Flags]
    public enum AlpcDisconnectPortFlags
    {
        None = 0,
        NoFlushOnClose = 1,
    }

    [Flags]
    public enum AlpcMessageFlags : uint
    {
        None = 0,
        ReplyMessage = 0x1,
        LpcMode = 0x2,
        ReleaseMessage = 0x10000,
        SyncRequest = 0x20000,
        WaitUserMode = 0x100000,
        WaitAlertable = 0x200000,
        Wow64Call = 0x80000000
    }

    public static class NtAlpcNativeMethods
    {
        [DllImport("ntdll.dll")]
        public static extern int AlpcMaxAllowedMessageLength();

        [DllImport("ntdll.dll")]
        public static extern int AlpcGetHeaderSize(int Flags);

        [DllImport("ntdll.dll")]
        public static extern NtStatus AlpcInitializeMessageAttribute(
            AlpcMessageAttributeFlags AttributeFlags,
            SafeAlpcMessageAttributesBuffer Buffer, // PALPC_MESSAGE_ATTRIBUTES 
            int BufferSize,
            out int RequiredBufferSize
        );

        [DllImport("ntdll.dll")]
        public static extern IntPtr AlpcGetMessageAttribute(
            SafeAlpcMessageAttributesBuffer Buffer, // PALPC_MESSAGE_ATTRIBUTES
            AlpcMessageAttributeFlags AttributeFlag
        );
    }

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcCreatePort(
            out SafeKernelObjectHandle PortHandle,
            [In] ObjectAttributes ObjectAttributes,
            [In] AlpcPortAttributes PortAttributes
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcDisconnectPort(
            [In] SafeKernelObjectHandle PortHandle,
            AlpcDisconnectPortFlags Flags
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcQueryInformation(
            SafeKernelObjectHandle PortHandle,
            AlpcPortInformationClass PortInformationClass,
            SafeBuffer PortInformation,
            int Length,
            out int ReturnLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcSetInformation(
            [In] SafeKernelObjectHandle PortHandle,
            AlpcPortInformationClass PortInformationClass,
            SafeBuffer PortInformation,
            int Length);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcConnectPort(
            out SafeKernelObjectHandle PortHandle,
            [In] UnicodeString PortName,
            [In] ObjectAttributes ObjectAttributes,
            [In] AlpcPortAttributes PortAttributes,
            AlpcMessageFlags Flags,
            [In] SafeSidBufferHandle RequiredServerSid,
            [In, Out] SafeAlpcPortMessageBuffer ConnectionMessage,
            [In, Out] OptionalInt32 BufferLength,
            [In, Out] SafeAlpcMessageAttributesBuffer OutMessageAttributes,
            [In, Out] SafeAlpcMessageAttributesBuffer InMessageAttributes,
            [In] LargeInteger Timeout
        );

        [DllImport("ntdll.dll")]
        [SupportedVersion(SupportedVersion.Windows8)]
        public static extern NtStatus NtAlpcConnectPortEx(
            out SafeKernelObjectHandle PortHandle,
            [In] ObjectAttributes ConnectionPortObjectAttributes,
            [In] ObjectAttributes ClientPortObjectAttributes,
            [In] AlpcPortAttributes PortAttributes,
            AlpcMessageFlags Flags,
            [In] SafeBuffer ServerSecurityRequirements, // SECURITY_DESCRIPTOR
            [In, Out] SafeAlpcPortMessageBuffer ConnectionMessage,
            [In, Out] OptionalLength BufferLength,
            [In, Out] SafeAlpcMessageAttributesBuffer OutMessageAttributes,
            [In, Out] SafeAlpcMessageAttributesBuffer InMessageAttributes,
            [In] LargeInteger Timeout);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcSendWaitReceivePort(
            [In] SafeKernelObjectHandle PortHandle,
            AlpcMessageFlags Flags,
            [In] SafeAlpcPortMessageBuffer SendMessage,
            [In, Out] SafeAlpcMessageAttributesBuffer SendMessageAttributes,
            [Out] SafeAlpcPortMessageBuffer ReceiveMessage,
            [In, Out] OptionalLength BufferLength,
            [In, Out] SafeAlpcMessageAttributesBuffer ReceiveMessageAttributes,
            [In] LargeInteger Timeout);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcCancelMessage(
            [In] SafeKernelObjectHandle PortHandle,
            uint Flags,
            [In] AlpcContextAttribute MessageContext
           );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcImpersonateClientOfPort(
                [In] SafeKernelObjectHandle PortHandle,
                [In] SafeAlpcPortMessageBuffer PortMessage,
                uint Flags
        );

        [DllImport("ntdll.dll")]
        [SupportedVersion(SupportedVersion.Windows10_TH2)]
        public static extern NtStatus NtAlpcImpersonateClientContainerOfPort(
            [In] SafeKernelObjectHandle PortHandle,
            [In] SafeAlpcPortMessageBuffer PortMessage,
            uint Flags
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcOpenSenderProcess(
            out SafeKernelObjectHandle ProcessHandle,
            [In] SafeKernelObjectHandle PortHandle,
            [In] SafeAlpcPortMessageBuffer PortMessage,
            uint Flags,
            ProcessAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcOpenSenderThread(
            out SafeKernelObjectHandle ThreadHandle,
            [In] SafeKernelObjectHandle PortHandle,
            [In] SafeAlpcPortMessageBuffer PortMessage,
            uint Flags,
            ProcessAccessRights DesiredAccess,
            [In] ObjectAttributes ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcCreateSecurityContext(
            SafeKernelObjectHandle PortHandle,
            int Flags,
            [In, Out] AlpcSecurityAttribute SecurityAttribute);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcDeleteSecurityContext(
            SafeKernelObjectHandle PortHandle,
            int Flags,
            IntPtr ContextHandle
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcRevokeSecurityContext(
            SafeKernelObjectHandle PortHandle,
            int Flags,
            IntPtr ContextHandle
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcQueryInformationMessage(
            SafeKernelObjectHandle PortHandle,
            SafeAlpcPortMessageBuffer PortMessage,
            AlpcMessageInformationClass MessageInformationClass,
            SafeBuffer MessageInformation,
            int Length,
            out int ReturnLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcCreatePortSection(
            SafeKernelObjectHandle PortHandle,
            AlpcDataViewAttrFlags Flags,
            SafeKernelObjectHandle SectionHandle,
            IntPtr SectionSize,
            out IntPtr AlpcSectionHandle,
            out IntPtr ActualSectionSize
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcDeletePortSection(
            SafeKernelObjectHandle PortHandle,
            int Flags,
            IntPtr SectionHandle
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcCreateResourceReserve(
            SafeKernelObjectHandle PortHandle,
            int Flags,
            IntPtr MessageSize,
            out IntPtr ResourceId
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcDeleteResourceReserve(
            SafeKernelObjectHandle PortHandle,
            int Flags,
            IntPtr ResourceId
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcCreateSectionView(
            SafeKernelObjectHandle PortHandle,
            int Flags,
            ref AlpcDataViewAttr ViewAttributes
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcDeleteSectionView(
            SafeKernelObjectHandle PortHandle,
            int Flags,
            IntPtr ViewBase
        );
    }
#pragma warning restore 1591
}
