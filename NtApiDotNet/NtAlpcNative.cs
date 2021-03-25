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

using NtApiDotNet.Utilities.Reflection;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
#pragma warning disable 1591
    /// <summary>
    /// Access rights for ALPC
    /// </summary>
    [Flags]
    public enum AlpcAccessRights : uint
    {
        [SDKName("PORT_CONNECT")]
        Connect = 0x1,
        [SDKName("GENERIC_READ")]
        GenericRead = GenericAccessRights.GenericRead,
        [SDKName("GENERIC_WRITE")]
        GenericWrite = GenericAccessRights.GenericWrite,
        [SDKName("GENERIC_EXECUTE")]
        GenericExecute = GenericAccessRights.GenericExecute,
        [SDKName("GENERIC_ALL")]
        GenericAll = GenericAccessRights.GenericAll,
        [SDKName("DELETE")]
        Delete = GenericAccessRights.Delete,
        [SDKName("READ_CONTROL")]
        ReadControl = GenericAccessRights.ReadControl,
        [SDKName("WRITE_DAC")]
        WriteDac = GenericAccessRights.WriteDac,
        [SDKName("WRITE_OWNER")]
        WriteOwner = GenericAccessRights.WriteOwner,
        [SDKName("SYNCHRONIZE")]
        Synchronize = GenericAccessRights.Synchronize,
        [SDKName("MAXIMUM_ALLOWED")]
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
        [SDKName("ACCESS_SYSTEM_SECURITY")]
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
        AlpcWaitForPortReferences,
        AlpcServerSessionInformation
    }

    public enum AlpcMessageInformationClass
    {
        AlpcMessageSidInformation = 0,
        AlpcMessageTokenModifiedIdInformation,
        AlpcMessageDirectStatusInformation,
        AlpcMessageHandleInformation,
    }

    public enum AlpcMessageType
    {
        None = 0,
        Request = 1,
        Reply = 2,
        Datagram = 3,
        LostReply = 4,
        PortClosed = 5,
        ClientDied = 6,
        Exception = 7,
        DebugEvent = 8,
        ErrorEvent = 9,
        ConnectionRequest = 10,
        // Used by the kernel when disconnecting an exception port.
        PortDisconnected = 13,
    }

    [Flags]
    public enum AlpcMessageTypeFlags
    {
        None = 0,
        Unknown1000 = 0x1000,
        ContinuationRequired = 0x2000,
        Unknown4000 = 0x4000,
        KernelModeCaller = 0x8000,
    }

    [StructLayout(LayoutKind.Sequential)]
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
            public int Length;
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
            public int ZeroInit;
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
            public int CallbackId;
        }
        public PortMessageUnion3 u3;

        internal AlpcPortMessage Clone()
        {
            return (AlpcPortMessage)MemberwiseClone();
        }
    }

    [Flags]
    public enum AlpcPortAttributeFlags
    {
        None = 0,
        LpcPort = 0x1000, // Not accessible outside the kernel.
        AllowImpersonation = 0x10000,
        AllowLpcRequests = 0x20000,
        WaitablePort = 0x40000,
        AllowDupObject = 0x80000,
        SystemProcess = 0x100000, // Not accessible outside the kernel.
        LrpcWakePolicy1 = 0x200000,
        LrpcWakePolicy2 = 0x400000,
        LrpcWakePolicy3 = 0x800000,
        DirectMessage = 0x1000000,
        /// <summary>
        /// If set then object duplication won't complete. Used by RPC to ensure
        /// multi-handle attributes don't fail when receiving.
        /// </summary>
        AllowMultiHandleAttribute = 0x2000000,
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
        public AlpcHandleObjectType DupObjectTypes;
        public int Reserved;

        public static AlpcPortAttributes CreateDefault()
        {
            return new AlpcPortAttributes()
            {
                Flags = AlpcPortAttributeFlags.None,
                SecurityQos = new SecurityQualityOfServiceStruct(SecurityImpersonationLevel.Impersonation,
                                                            SecurityContextTrackingMode.Static, false),
                MaxMessageLength = new IntPtr(short.MaxValue),
                DupObjectTypes = AlpcHandleObjectType.AllObjects
            };
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AlpcHandle
    {
        private IntPtr _value;

        public long Value
        {
            get => _value.ToInt64();
            set => _value = new IntPtr(value);
        }

        public AlpcHandle(long value)
        {
            _value = new IntPtr(value);
        }
        
        public static implicit operator AlpcHandle(long value)
        {
            return new AlpcHandle(value);
        }
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
        AllAttributes = WorkOnBehalfOf | Direct | Token | Handle | Context | View | Security
    }

    [Flags]
    public enum AlpcSecurityAttrFlags
    {
        None = 0,
        ReleaseHandle = 0x10000,
        CreateHandle = 0x20000
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AlpcSecurityAttr
    {
        public AlpcSecurityAttrFlags Flags;
        public IntPtr QoS; // struct _SECURITY_QUALITY_OF_SERVICE
        public AlpcHandle ContextHandle;
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
    public struct AlpcWorkOnBehalfAttr
    {
        public int ThreadId;
        public int ThreadCreationTimeLow;
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

    [Flags]
    public enum AlpcHandleObjectType
    {
        None = 0,
        File = 0x0001,
        Invalid0002 = 0x0002,
        Thread = 0x0004,
        Semaphore = 0x0008,
        Event = 0x0010,
        Process = 0x0020,
        Mutex = 0x0040,
        Section = 0x0080,
        RegKey = 0x0100,
        Token = 0x0200,
        Composition = 0x0400,
        Job = 0x0800,
        AllObjects = File | Thread | Semaphore | Event
            | Process | Mutex | Section | RegKey | Token
            | Composition | Job
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AlpcHandleAttr
    {
        public AlpcHandleAttrFlags Flags;
        public IntPtr Handle;
        public AlpcHandleObjectType ObjectType;
        public AccessMask DesiredAccess;
    }

    public struct AlpcHandleAttrIndirect
    {
        public AlpcHandleAttrFlags Flags;
        public IntPtr HandleAttrArray;
        public int HandleCount;
        public AccessMask GrantedAccess;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AlpcHandleAttr32
    {
        public AlpcHandleAttrFlags Flags;
        public int Handle;
        public AlpcHandleObjectType ObjectType;
        public AccessMask DesiredAccess;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AlpcMessageHandleInformation
    {
        public int Index;
        public AlpcHandleAttrFlags Flags;
        public int Handle;
        public AlpcHandleObjectType ObjectType;
        public AccessMask GrantedAccess;
    }

    [Flags]
    public enum AlpcDataViewAttrFlags
    {
        None = 0,
        /// <summary>
        /// Use in a reply to release the view.
        /// </summary>
        ReleaseView = 0x10000,
        /// <summary>
        /// Automatically release the view once it's passed to the receiver. 
        /// </summary>
        AutoRelease = 0x20000,
        /// <summary>
        /// Make the data view secure.
        /// </summary>
        Secure = 0x40000
    }

    [Flags]
    public enum AlpcCreatePortSectionFlags
    {
        None = 0,
        Secure = 0x40000
    }

    [Flags]
    public enum AlpcDeletePortSectionFlags
    {
        None = 0
    }

    [Flags]
    public enum AlpcCreateSectionViewFlags
    {
        None = 0,
    }

    [Flags]
    public enum AlpcCreateResourceReserveFlags
    {
        None = 0,
    }

    [Flags]
    public enum AlpcDeleteResourceReserveFlags
    {
        None = 0,
    }

    [Flags]
    public enum AlpcDeleteSectionViewFlags
    {
        None = 0,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AlpcDataViewAttr
    {
        public AlpcDataViewAttrFlags Flags;
        public AlpcHandle SectionHandle;
        public IntPtr ViewBase;
        public IntPtr ViewSize;
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
        TrackPortReferences = 0x40000,
        WaitUserMode = 0x100000,
        WaitAlertable = 0x200000,
        WaitChargePolicy = 0x400000,
        Unknown1000000 = 0x1000000,
        /// <summary>
        /// When used all structures passed to kernel need to be 64 bit versions.
        /// </summary>
        Wow64Call = 0x40000000,
    }

    [Flags]
    public enum AlpcCancelMessageFlags
    {
        None = 0,
        TryCancel = 1,
        Unknown2 = 2,
        Unknown4 = 4,
        NoContextCheck = 8
    }

    [Flags]
    public enum AlpcImpersonationClientOfPortFlags
    {
        None = 0,
        AnonymousFallback = 1,
        RequireImpersonationLevel = 2,
        // From bit 2 on it's the impersonation level required.
    }

    [Flags]
    public enum AlpcImpersonateClientContainerOfPortFlags
    {
        None = 0,
    }

    [Flags]
    public enum AlpcCreateSecurityContextFlags
    {
        None = 0,
    }

    [Flags]
    public enum AlpcDeleteSecurityContextFlags
    {
        None = 0,
    }

    [Flags]
    public enum AlpcRevokeSecurityContextFlags
    {
        None = 0,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AlpcBasicInformation
    {
        public AlpcPortAttributeFlags Flags;
        public int SequenceNo;
        public IntPtr PortContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AlpcPortAssociateCompletionPort
    {
        public IntPtr CompletionKey;
        public IntPtr CompletionPort;
    }

    // Output structure for server information. You need to specify waiting handle.
    public struct AlpcServerInformationOut
    {
        public byte ThreadBlocked;
        public IntPtr ConnectedProcessId;
        public UnicodeStringOut ConnectionPortName;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct AlpcServerInformation
    {
        [FieldOffset(0)]
        public IntPtr ThreadHandle;
        [FieldOffset(0)]
        public AlpcServerInformationOut Out;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AlpcPortMessageZoneInformation
    {
        public IntPtr Buffer;
        public int Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AlpcPortCompletionListInformation
    {
        public IntPtr Buffer; // PALPC_COMPLETION_LIST_HEADER
        public int Size;
        public int ConcurrencyCount;
        public int AttributeFlags;
    }

    [Flags]
    public enum AlpcOpenSenderProcessFlags
    {
        None = 0,
    }

    [Flags]
    public enum AlpcOpenSenderThreadFlags
    {
        None = 0,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AlpcServerSessionInformation
    {
        public int SessionId;
        public int ProcessId;
    }

    public static class NtAlpcNativeMethods
    {
        [DllImport("ntdll.dll")]
        public static extern int AlpcMaxAllowedMessageLength();

        [DllImport("ntdll.dll")]
        public static extern int AlpcGetHeaderSize(AlpcMessageAttributeFlags Flags);

        [DllImport("ntdll.dll")]
        public static extern NtStatus AlpcInitializeMessageAttribute(
            AlpcMessageAttributeFlags AttributeFlags,
            SafeAlpcMessageAttributesBuffer Buffer,
            int BufferSize,
            out int RequiredBufferSize
        );

        [DllImport("ntdll.dll")]
        public static extern IntPtr AlpcGetMessageAttribute(
            SafeAlpcMessageAttributesBuffer Buffer,
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
            [In, Out] OptionalLength BufferLength,
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
        public static extern NtStatus NtAlpcImpersonateClientOfPort(
                [In] SafeKernelObjectHandle PortHandle,
                [In] AlpcPortMessage PortMessage,
                AlpcImpersonationClientOfPortFlags Flags
        );

        [DllImport("ntdll.dll")]
        [SupportedVersion(SupportedVersion.Windows10_TH2)]
        public static extern NtStatus NtAlpcImpersonateClientContainerOfPort(
            [In] SafeKernelObjectHandle PortHandle,
            [In] AlpcPortMessage PortMessage,
            AlpcImpersonateClientContainerOfPortFlags Flags
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcCreateSecurityContext(
            SafeKernelObjectHandle PortHandle,
            AlpcCreateSecurityContextFlags Flags,
            ref AlpcSecurityAttr SecurityAttribute);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcDeleteSecurityContext(
            SafeKernelObjectHandle PortHandle,
            AlpcDeleteSecurityContextFlags Flags,
            AlpcHandle ContextHandle
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcRevokeSecurityContext(
            SafeKernelObjectHandle PortHandle,
            AlpcRevokeSecurityContextFlags Flags,
            AlpcHandle ContextHandle
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcQueryInformationMessage(
            SafeKernelObjectHandle PortHandle,
            AlpcPortMessage PortMessage,
            AlpcMessageInformationClass MessageInformationClass,
            SafeBuffer MessageInformation,
            int Length,
            out int ReturnLength
        );

        // Version to support AlpcMessageDirectStatusInformation which needs ReturnLength == NULL.
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcQueryInformationMessage(
            SafeKernelObjectHandle PortHandle,
            AlpcPortMessage PortMessage,
            AlpcMessageInformationClass MessageInformationClass,
            IntPtr MessageInformation,
            int Length,
            IntPtr ReturnLength
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcCreatePortSection(
            SafeKernelObjectHandle PortHandle,
            AlpcCreatePortSectionFlags Flags,
            SafeKernelObjectHandle SectionHandle,
            IntPtr SectionSize,
            out AlpcHandle AlpcSectionHandle,
            out IntPtr ActualSectionSize
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcDeletePortSection(
            SafeKernelObjectHandle PortHandle,
            AlpcDeletePortSectionFlags Flags,
            AlpcHandle SectionHandle
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcCreateResourceReserve(
            SafeKernelObjectHandle PortHandle,
            AlpcCreateResourceReserveFlags Flags,
            IntPtr MessageSize,
            out AlpcHandle ResourceId
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcDeleteResourceReserve(
            SafeKernelObjectHandle PortHandle,
            AlpcDeleteResourceReserveFlags Flags,
            AlpcHandle ResourceId
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcCreateSectionView(
            SafeKernelObjectHandle PortHandle,
            AlpcCreateSectionViewFlags Flags,
            ref AlpcDataViewAttr ViewAttributes
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcDeleteSectionView(
            SafeKernelObjectHandle PortHandle,
            AlpcDeleteSectionViewFlags Flags,
            IntPtr ViewBase
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcAcceptConnectPort(
            out SafeKernelObjectHandle PortHandle,
            SafeKernelObjectHandle ConnectionPortHandle,
            AlpcMessageFlags Flags,
            ObjectAttributes ObjectAttributes,
            AlpcPortAttributes PortAttributes,
            IntPtr PortContext,
            SafeAlpcPortMessageBuffer ConnectionRequest,
            SafeAlpcMessageAttributesBuffer ConnectionMessageAttributes,
            bool AcceptConnection
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcOpenSenderProcess(
            out SafeKernelObjectHandle ProcessHandle,
            SafeKernelObjectHandle PortHandle,
            AlpcPortMessage PortMessage,
            AlpcOpenSenderProcessFlags Flags,
            ProcessAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcOpenSenderThread(
            out SafeKernelObjectHandle ThreadHandle,
            SafeKernelObjectHandle PortHandle,
            AlpcPortMessage PortMessage,
            AlpcOpenSenderThreadFlags Flags,
            ThreadAccessRights DesiredAccess,
            ObjectAttributes ObjectAttributes
        );

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcCancelMessage(
            SafeKernelObjectHandle PortHandle,
            AlpcCancelMessageFlags Flags,
            ref AlpcContextAttr MessageContext
        );
    }
#pragma warning restore 1591
}
