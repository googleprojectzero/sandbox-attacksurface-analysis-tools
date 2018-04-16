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

    [Flags]
    public enum AlpcPortAttributeFlags
    {
        None = 0,
        LpcPort = 0x1000, // Not accessible outside the kernel.
        AllowLpcRequests = 0x20000,
        WaitablePort = 0x40000,
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
    public enum AlpcHandleAttributeFlags
    {
        DuplicateSameAccess = 0x10000,
        DuplicateSameAttributes = 0x20000,
        DuplicateInherit = 0x80000,
    }

    [StructLayout(LayoutKind.Sequential)]
    public class AlpcHandleAttribute
    {
        public AlpcHandleAttributeFlags Flags;
        public IntPtr Handle;
        public int ObjectType; 
        public AccessMask DesiredAccess;
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

    [StructLayout(LayoutKind.Sequential)]
    public class AlpcMessageAtributes
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

    public static partial class NtSystemCalls
    {
        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcCreatePort(
            out SafeKernelObjectHandle PortHandle,
            [In] ObjectAttributes ObjectAttributes,
            [In, Optional] AlpcPortAttributes PortAttributes
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
            [Optional] uint Flags,
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
            [Optional] uint Flags,
            [Optional] IntPtr ServerSecurityRequirements, // SECURITY_DESCRIPTOR
            [Optional, In, Out] AlpcPortMessage ConnectionMessage,
            [Optional, In, Out] OptionalLength BufferLength,
            [Optional, In, Out] AlpcMessageAtributes OutMessageAttributes,
            [Optional, In, Out] AlpcMessageAtributes InMessageAttributes,
            [Optional, In] LargeInteger Timeout);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcSendWaitReceivePort(
            [In] SafeKernelObjectHandle PortHandle,
            [Optional] uint Flags,
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
            [In] AlpcContextAttribute MessageContext
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

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtAlpcCreateSecurityContext(
            SafeKernelObjectHandle PortHandle,
            int Flags,
            [In, Out] AlpcSecurityAttribute SecurityAttribute);
    }
#pragma warning restore 1591

    /// <summary>
    /// Class to represent an ALPC port.
    /// </summary>
    [NtType("ALPC Port")]
    public class NtAlpc : NtObjectWithDuplicate<NtAlpc, AlpcAccessRights>
    {
        internal NtAlpc(SafeKernelObjectHandle handle) : base(handle)
        {
        }

        /// <summary>
        /// Create an ALPC port.
        /// </summary>
        /// <param name="object_attributes">The object attributes for the port.</param>
        /// <param name="port_attributes">The attributes for the port.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The created object.</returns>
        public static NtResult<NtAlpc> Create(ObjectAttributes object_attributes, AlpcPortAttributes port_attributes, bool throw_on_error)
        {
            return NtSystemCalls.NtAlpcCreatePort(out SafeKernelObjectHandle handle, object_attributes, port_attributes).CreateResult(throw_on_error, () => new NtAlpc(handle));
        }

        /// <summary>
        /// Create an ALPC port.
        /// </summary>
        /// <param name="object_attributes">The object attributes for the port.</param>
        /// <param name="port_attributes">The attributes for the port.</param>
        /// <returns>The created object.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtAlpc Create(ObjectAttributes object_attributes, AlpcPortAttributes port_attributes)
        {
            return Create(object_attributes, port_attributes, true).Result;
        }

        /// <summary>
        /// Create an ALPC port.
        /// </summary>
        /// <param name="port_name">The name of the port to create.</param>
        /// <param name="port_attributes">The attributes for the port.</param>
        /// <returns>The created object.</returns>
        /// <exception cref="NtException">Thrown on error.</exception>
        public static NtAlpc Create(string port_name = null, AlpcPortAttributes port_attributes = null)
        {
            using (var obj_attr = new ObjectAttributes(port_name, AttributeFlags.CaseInsensitive))
            {
                return Create(obj_attr, port_attributes);
            }
        }

        /// <summary>
        /// Connect to an ALPC port.
        /// </summary>
        /// <param name="port_name">The name of the port to connect to.</param>
        /// <param name="port_attributes">Attributes for the port.</param>
        /// <returns>The connected ALPC port object.</returns>
        public static NtAlpc Connect(string port_name, AlpcPortAttributes port_attributes = null)
        {
            AlpcPortAttributes attrs = new AlpcPortAttributes();
            NtSystemCalls.NtAlpcConnectPort(out SafeKernelObjectHandle handle, 
                new UnicodeString(port_name), null, port_attributes, 0).ToNtException();
            return new NtAlpc(handle);
        }

        /// <summary>
        /// Dispose port.
        /// </summary>
        /// <param name="disposing">True when disposing, false if finalizing</param>
        protected override void Dispose(bool disposing)
        {
            NtSystemCalls.NtAlpcDisconnectPort(Handle, 0);
            base.Dispose(disposing);
        }
    }
}
