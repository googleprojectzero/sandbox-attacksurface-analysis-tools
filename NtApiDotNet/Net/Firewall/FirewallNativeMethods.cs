//  Copyright 2021 Google LLC. All Rights Reserved.
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

using Microsoft.Win32.SafeHandles;
using NtApiDotNet.Utilities.Reflection;
using NtApiDotNet.Win32;
using NtApiDotNet.Win32.Rpc.Transport;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Runtime.InteropServices;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace NtApiDotNet.Net.Firewall
{
    public enum FirewallDataType
    {
        [SDKName("FWP_EMPTY")]
        Empty = 0,
        [SDKName("FWP_UINT8")]
        UInt8 = Empty + 1,
        [SDKName("FWP_UINT16")]
        UInt16 = UInt8 + 1,
        [SDKName("FWP_UINT32")]
        UInt32 = UInt16 + 1,
        [SDKName("FWP_UINT64")]
        UInt64 = UInt32 + 1,
        [SDKName("FWP_INT8")]
        Int8 = UInt64 + 1,
        [SDKName("FWP_INT16")]
        Int16 = Int8 + 1,
        [SDKName("FWP_INT32")]
        Int32 = Int16 + 1,
        [SDKName("FWP_INT64")]
        Int64 = Int32 + 1,
        [SDKName("FWP_FLOAT")]
        Float = Int64 + 1,
        [SDKName("FWP_DOUBLE")]
        Double = Float + 1,
        [SDKName("FWP_BYTE_ARRAY16_TYPE")]
        ByteArray16 = Double + 1,
        [SDKName("FWP_BYTE_BLOB_TYPE")]
        ByteBlob = ByteArray16 + 1,
        [SDKName("FWP_SID")]
        Sid = ByteBlob + 1,
        [SDKName("FWP_SECURITY_DESCRIPTOR_TYPE")]
        SecurityDescriptor = Sid + 1,
        [SDKName("FWP_TOKEN_INFORMATION_TYPE")]
        TokenInformation = SecurityDescriptor + 1,
        [SDKName("FWP_TOKEN_ACCESS_INFORMATION_TYPE")]
        TokenAccessInformation = TokenInformation + 1,
        [SDKName("FWP_UNICODE_STRING_TYPE")]
        UnicodeString = TokenAccessInformation + 1,
        [SDKName("FWP_BYTE_ARRAY6_TYPE")]
        ByteArray6 = UnicodeString + 1,
        [SDKName("FWP_BITMAP_INDEX_TYPE")]
        BitmapIndex = ByteArray6 + 1,
        [SDKName("FWP_BITMAP_ARRAY64_TYPE")]
        BitmapArray64 = BitmapIndex + 1,
        [SDKName("FWP_SINGLE_DATA_TYPE_MAX")]
        SingleDataTypeMax = 0xff,
        [SDKName("FWP_V4_ADDR_MASK")]
        V4AddrMask = SingleDataTypeMax + 1,
        [SDKName("FWP_V6_ADDR_MASK")]
        V6AddrMask = V4AddrMask + 1,
        [SDKName("FWP_RANGE_TYPE")]
        Range = V6AddrMask + 1,
        [SDKName("FWP_DATA_TYPE_MAX")]
        DataTypeMax = Range + 1
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct FWPM_DISPLAY_DATA0
    {
        /* [unique][string] */
        [MarshalAs(UnmanagedType.LPWStr)]
        public string name;
        /* [unique][string] */
        [MarshalAs(UnmanagedType.LPWStr)]
        public string description;
    }

    [Flags]
    public enum FirewallSessionFlags
    {
        None = 0,
        [SDKName("FWPM_SESSION_FLAG_DYNAMIC")]
        Dynamic = 0x00000001,
        [SDKName("FWPM_SESSION_FLAG_RESERVED")]
        Reserved = 0x10000000
    }

    [StructLayout(LayoutKind.Sequential)]
    class FWPM_SESSION0
    {
        public Guid sessionKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public FirewallSessionFlags flags;
        public int txnWaitTimeoutInMSec;
        public int processId;
        public IntPtr sid; // SID* 
        [MarshalAs(UnmanagedType.LPWStr)]
        public string username;
        [MarshalAs(UnmanagedType.Bool)]
        public bool kernelMode;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct FWP_BYTE_BLOB
    {
        public int size;
        /* [unique][size_is] */
        public IntPtr data;

        public byte[] ToArray()
        {
            if (size <= 0 || data == IntPtr.Zero)
            {
                return new byte[0];
            }
            byte[] ret = new byte[size];
            Marshal.Copy(data, ret, 0, ret.Length);
            return ret;
        }

    }

    [StructLayout(LayoutKind.Sequential)]
    struct FWP_RANGE0
    {
        public FWP_VALUE0 valueLow;
        public FWP_VALUE0 valueHigh;
    }

    [StructLayout(LayoutKind.Explicit)]
    struct FWP_VALUE0_UNION
    {
        [FieldOffset(0)]
        public byte uint8;
        [FieldOffset(0)]
        public ushort uint16;
        [FieldOffset(0)]
        public uint uint32;
        [FieldOffset(0)]
        public IntPtr uint64; // UINT64*
        [FieldOffset(0)]
        public sbyte int8;
        [FieldOffset(0)]
        public short int16;
        [FieldOffset(0)]
        public int int32;
        [FieldOffset(0)]
        public IntPtr int64; // INT64* 
        [FieldOffset(0)]
        public float float32;
        [FieldOffset(0)]
        public IntPtr double64; // double* 
        [FieldOffset(0)]
        public IntPtr byteArray16; // FWP_BYTE_ARRAY16* 
        [FieldOffset(0)]
        public IntPtr byteBlob; // FWP_BYTE_BLOB*
        [FieldOffset(0)]
        public IntPtr sid; // SID* 
        [FieldOffset(0)]
        public IntPtr sd; // FWP_BYTE_BLOB* 
        [FieldOffset(0)]
        public IntPtr tokenInformation; // FWP_TOKEN_INFORMATION* 
        [FieldOffset(0)]
        public IntPtr tokenAccessInformation; // FWP_BYTE_BLOB* 
        [FieldOffset(0)]
        public IntPtr unicodeString; // LPWSTR 
        [FieldOffset(0)]
        public IntPtr byteArray6; // FWP_BYTE_ARRAY6* 
        [FieldOffset(0)]
        public IntPtr bitmapArray64; // FWP_BITMAP_ARRAY64*
        [FieldOffset(0)]
        public IntPtr v4AddrMask; // FWP_V4_ADDR_AND_MASK* 
        [FieldOffset(0)]
        public IntPtr v6AddrMask; // FWP_V6_ADDR_AND_MASK* 
        [FieldOffset(0)]
        public IntPtr rangeValue; // FWP_RANGE0* 
    }

    [StructLayout(LayoutKind.Sequential)]
    struct FWP_VALUE0
    {
        public FirewallDataType type;
        public FWP_VALUE0_UNION value;
    }

    [StructLayout(LayoutKind.Explicit)]
    struct FWPM_ACTION0_UNION
    {
        [FieldOffset(0)]
        public Guid filterType;
        [FieldOffset(0)]
        public Guid calloutKey;
        [FieldOffset(0)]
        public byte bitmapIndex;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct FWPM_ACTION0
    {
        public FirewallActionType type;
        public FWPM_ACTION0_UNION action;
    }

    [StructLayout(LayoutKind.Explicit)]
    struct FWPM_FILTER0_UNION
    {
        [FieldOffset(0)]
        public ulong rawContext;
        [FieldOffset(0)]
        public Guid providerContextKey;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct FWPM_FILTER0
    {
        public Guid filterKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public FirewallFilterFlags flags;
        public IntPtr providerKey; // GUID*
        public FWP_BYTE_BLOB providerData;
        public Guid layerKey;
        public Guid subLayerKey;
        public FWP_VALUE0 weight;
        public int numFilterConditions;
        public IntPtr filterCondition; // FWPM_FILTER_CONDITION0* 
        public FWPM_ACTION0 action;
        public FWPM_FILTER0_UNION context;
        public IntPtr reserved; // GUID* 
        public ulong filterId;
        public FWP_VALUE0 effectiveWeight;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct FWPM_FILTER_CONDITION0
    {
        public Guid fieldKey;
        public FirewallMatchType matchType;
        public FWP_VALUE0 conditionValue;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct FWP_V4_ADDR_AND_MASK
    {
        public uint addr;
        public uint mask;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct FWP_V6_ADDR_AND_MASK
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] addr;
        public byte prefixLength;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct FWP_TOKEN_INFORMATION
    {
        public int sidCount;
        public IntPtr sids; // PSID_AND_ATTRIBUTES 
        public int restrictedSidCount;
        public IntPtr restrictedSids; // PSID_AND_ATTRIBUTES 
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct FWP_BITMAP_ARRAY64
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] bitmapArray64;
    }

    public enum FWP_FILTER_ENUM_TYPE
    {
        FWP_FILTER_ENUM_FULLY_CONTAINED = 0,
        FWP_FILTER_ENUM_OVERLAPPING = FWP_FILTER_ENUM_FULLY_CONTAINED + 1,
        FWP_FILTER_ENUM_TYPE_MAX = FWP_FILTER_ENUM_OVERLAPPING + 1
    }

    [Flags]
    public enum FilterEnumFlags
    {
        None = 0,
        [SDKName("FWP_FILTER_ENUM_FLAG_BEST_TERMINATING_MATCH")]
        BestTerminatingMatch = 0x00000001,
        [SDKName("FWP_FILTER_ENUM_FLAG_SORTED")]
        Sorted = 0x00000002,
        [SDKName("FWP_FILTER_ENUM_FLAG_BOOTTIME_ONLY")]
        BoottimeOnly = 0x00000004,
        [SDKName("FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME")]
        IncludeBoottime = 0x00000008,
        [SDKName("FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED")]
        IncludeDisabled = 0x00000010,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    class FWPM_FILTER_ENUM_TEMPLATE0
    {
        public IntPtr providerKey;
        public Guid layerKey;
        public FWP_FILTER_ENUM_TYPE enumType;
        public FilterEnumFlags flags;
        public IntPtr providerContextTemplate; // FWPM_PROVIDER_CONTEXT_ENUM_TEMPLATE0*
        public int numFilterConditions;
        public IntPtr filterCondition; // FWPM_FILTER_CONDITION0* 
        public FirewallActionType actionMask;
        public IntPtr calloutKey; // GUID*
    }

    class SafeFwpmEngineHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SafeFwpmEngineHandle() : base(true)
        {
        }

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        static extern Win32Error FwpmEngineClose0(IntPtr engineHandle);

        protected override bool ReleaseHandle()
        {
            return FwpmEngineClose0(handle) == Win32Error.SUCCESS;
        }
    }

    class SafeFwpmFilterEnumHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private readonly SafeFwpmEngineHandle _engine_handle;

        internal SafeFwpmFilterEnumHandle(SafeFwpmEngineHandle engine_handle, IntPtr handle) : base(true)
        {
            _engine_handle = engine_handle;
            SetHandle(handle);
        }

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        static extern Win32Error FwpmFilterDestroyEnumHandle0(
            SafeFwpmEngineHandle engineHandle,
            IntPtr enumHandle
        );

        protected override bool ReleaseHandle()
        {
            return FwpmFilterDestroyEnumHandle0(_engine_handle, handle) == Win32Error.SUCCESS;
        }
    }

    class SafeFwpmLayerEnumHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private readonly SafeFwpmEngineHandle _engine_handle;

        internal SafeFwpmLayerEnumHandle(SafeFwpmEngineHandle engine_handle, IntPtr handle) : base(true)
        {
            _engine_handle = engine_handle;
            SetHandle(handle);
        }

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        static extern Win32Error FwpmLayerDestroyEnumHandle0(
            SafeFwpmEngineHandle engineHandle,
            IntPtr enumHandle
        );

        protected override bool ReleaseHandle()
        {
            return FwpmLayerDestroyEnumHandle0(_engine_handle, handle) == Win32Error.SUCCESS;
        }
    }

    class SafeFwpmSubLayerEnumHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private readonly SafeFwpmEngineHandle _engine_handle;

        internal SafeFwpmSubLayerEnumHandle(SafeFwpmEngineHandle engine_handle, IntPtr handle) : base(true)
        {
            _engine_handle = engine_handle;
            SetHandle(handle);
        }


        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        static extern Win32Error FwpmSubLayerDestroyEnumHandle0(
           SafeFwpmEngineHandle engineHandle,
           IntPtr enumHandle
        );

        protected override bool ReleaseHandle()
        {
            return FwpmSubLayerDestroyEnumHandle0(_engine_handle, handle) == Win32Error.SUCCESS;
        }
    }



    class SafeFwpmMemoryBuffer : SafeBufferGeneric
    {
        internal SafeFwpmMemoryBuffer()
            : base(IntPtr.Zero, 0, true)
        {
        }

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        static extern void FwpmFreeMemory0(
            ref IntPtr p
        );

        protected override bool ReleaseHandle()
        {
            FwpmFreeMemory0(ref handle);
            return true;
        }
    }

    enum FWPM_FIELD_TYPE
    {
        FWPM_FIELD_RAW_DATA = 0,
        FWPM_FIELD_IP_ADDRESS = FWPM_FIELD_RAW_DATA + 1,
        FWPM_FIELD_FLAGS = FWPM_FIELD_IP_ADDRESS + 1,
        FWPM_FIELD_TYPE_MAX = FWPM_FIELD_FLAGS + 1
    }

    [StructLayout(LayoutKind.Sequential)]
    struct FWPM_FIELD0
    {
        /* [ref] */
        public IntPtr fieldKey; // GUID* 
        public FWPM_FIELD_TYPE type;
        public FirewallDataType dataType;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct FWPM_LAYER0
    {
        public Guid layerKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public FirewallLayerFlags flags;
        public int numFields;
        public IntPtr field; // FWPM_FIELD0*
        public Guid defaultSubLayerKey;
        public ushort layerId;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct FWPM_SUBLAYER0
    {
        public Guid subLayerKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public FirewallSubLayerFlags flags;
        /* [unique] */
        public IntPtr providerKey; // GUID* 
        public FWP_BYTE_BLOB providerData;
        public ushort weight;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct FWPM_CALLOUT0
    {
        public Guid calloutKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public FirewallCalloutFlags flags;
        public IntPtr providerKey; // GUID* 
        public FWP_BYTE_BLOB providerData;
        public Guid applicableLayer;
        public int calloutId;
    }

    internal static class FirewallNativeMethods
    {
        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmEngineOpen0(
            [Optional] string serverName,
            RpcAuthenticationType authnService,
            SEC_WINNT_AUTH_IDENTITY authIdentity,
            FWPM_SESSION0 session,
            out SafeFwpmEngineHandle engineHandle
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmFilterDestroyEnumHandle0(
            SafeFwpmEngineHandle engineHandle,
            IntPtr enumHandle
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmFilterCreateEnumHandle0(
            SafeFwpmEngineHandle engineHandle,
            SafeBuffer enumTemplate, // FWPM_FILTER_ENUM_TEMPLATE0*
            out IntPtr enumHandle
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmFilterEnum0(
           SafeFwpmEngineHandle engineHandle,
           IntPtr enumHandle,
           int numEntriesRequested,
           out SafeFwpmMemoryBuffer entries, // FWPM_FILTER0***
           out int numEntriesReturned
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmFilterGetByKey0(
          SafeFwpmEngineHandle engineHandle,
          in Guid key,
          out SafeFwpmMemoryBuffer filter // FWPM_FILTER0 **
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern void FwpmFreeMemory0(
            ref IntPtr p
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmEngineGetSecurityInfo0(
            SafeFwpmEngineHandle engineHandle,
            SecurityInformation securityInfo,
            IntPtr sidOwner,
            IntPtr sidGroup,
            IntPtr dacl,
            IntPtr sacl,
            out SafeFwpmMemoryBuffer securityDescriptor
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmConnectionGetSecurityInfo0(
            SafeFwpmEngineHandle engineHandle,
            SecurityInformation securityInfo,
            IntPtr sidOwner,
            IntPtr sidGroup,
            IntPtr dacl,
            IntPtr sacl,
            out SafeFwpmMemoryBuffer securityDescriptor
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmNetEventsGetSecurityInfo0(
            SafeFwpmEngineHandle engineHandle,
            SecurityInformation securityInfo,
            IntPtr sidOwner,
            IntPtr sidGroup,
            IntPtr dacl,
            IntPtr sacl,
            out SafeFwpmMemoryBuffer securityDescriptor
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmFilterGetSecurityInfoByKey0(
            SafeFwpmEngineHandle engineHandle,
            in Guid key,
            SecurityInformation securityInfo,
            IntPtr sidOwner,
            IntPtr sidGroup,
            IntPtr dacl,
            IntPtr sacl,
            out SafeFwpmMemoryBuffer securityDescriptor
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmCalloutGetSecurityInfoByKey0(
            SafeFwpmEngineHandle engineHandle,
            in Guid key,
            SecurityInformation securityInfo,
            IntPtr sidOwner,
            IntPtr sidGroup,
            IntPtr dacl,
            IntPtr sacl,
            out SafeFwpmMemoryBuffer securityDescriptor
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmLayerGetSecurityInfoByKey0(
            SafeFwpmEngineHandle engineHandle,
            in Guid key,
            SecurityInformation securityInfo,
            IntPtr sidOwner,
            IntPtr sidGroup,
            IntPtr dacl,
            IntPtr sacl,
            out SafeFwpmMemoryBuffer securityDescriptor
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmProviderContextGetSecurityInfoByKey0(
            SafeFwpmEngineHandle engineHandle,
            in Guid key,
            SecurityInformation securityInfo,
            IntPtr sidOwner,
            IntPtr sidGroup,
            IntPtr dacl,
            IntPtr sacl,
            out SafeFwpmMemoryBuffer securityDescriptor
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmProviderGetSecurityInfoByKey0(
            SafeFwpmEngineHandle engineHandle,
            in Guid key,
            SecurityInformation securityInfo,
            IntPtr sidOwner,
            IntPtr sidGroup,
            IntPtr dacl,
            IntPtr sacl,
            out SafeFwpmMemoryBuffer securityDescriptor
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmSubLayerGetSecurityInfoByKey0(
            SafeFwpmEngineHandle engineHandle,
            in Guid key,
            SecurityInformation securityInfo,
            IntPtr sidOwner,
            IntPtr sidGroup,
            IntPtr dacl,
            IntPtr sacl,
            out SafeFwpmMemoryBuffer securityDescriptor
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmLayerCreateEnumHandle0(
            SafeFwpmEngineHandle engineHandle,
            SafeBuffer enumTemplate, // FWPM_LAYER_ENUM_TEMPLATE0*
            out IntPtr enumHandle
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmLayerEnum0(
           SafeFwpmEngineHandle engineHandle,
           IntPtr enumHandle,
           int numEntriesRequested,
           out SafeFwpmMemoryBuffer entries, // FWPM_LAYER0***
           out int numEntriesReturned
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmLayerGetByKey0(
          SafeFwpmEngineHandle engineHandle,
          in Guid key,
          out SafeFwpmMemoryBuffer layer // FWPM_LAYER0**
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmLayerDestroyEnumHandle0(
            SafeFwpmEngineHandle engineHandle,
            IntPtr enumHandle
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmSubLayerCreateEnumHandle0(
            SafeFwpmEngineHandle engineHandle,
            SafeBuffer enumTemplate, // FWPM_SUBLAYER_ENUM_TEMPLATE0* 
            out IntPtr enumHandle
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmSubLayerEnum0(
           SafeFwpmEngineHandle engineHandle,
           IntPtr enumHandle,
           int numEntriesRequested,
           out SafeFwpmMemoryBuffer entries, // FWPM_SUBLAYER0***
           out int numEntriesReturned
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmSubLayerGetByKey0(
            SafeFwpmEngineHandle engineHandle,
            in Guid key,
            out SafeFwpmMemoryBuffer sublayer // FWPM_SUBLAYER0**
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmSubLayerDestroyEnumHandle0(
           SafeFwpmEngineHandle engineHandle,
           IntPtr enumHandle
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmSessionCreateEnumHandle0(
            SafeFwpmEngineHandle engineHandle,
            IntPtr enumTemplate, // FWPM_SESSION_ENUM_TEMPLATE0* 
            out IntPtr enumHandle
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmSessionEnum0(
            SafeFwpmEngineHandle engineHandle,
            IntPtr enumHandle,
            int numEntriesRequested,
            out SafeFwpmMemoryBuffer entries, // FWPM_SESSION0*** 
            out int numEntriesReturned
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmSessionDestroyEnumHandle0(
           SafeFwpmEngineHandle engineHandle,
           IntPtr enumHandle
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmGetAppIdFromFileName0(
            string fileName,
            out SafeFwpmMemoryBuffer appId // FWP_BYTE_BLOB
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmCalloutCreateEnumHandle0(
            SafeFwpmEngineHandle engineHandle,
            SafeBuffer enumTemplate,  // const FWPM_CALLOUT_ENUM_TEMPLATE0*
            out IntPtr enumHandle
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmCalloutEnum0(
            SafeFwpmEngineHandle engineHandle,
            IntPtr enumHandle,
            int numEntriesRequested,
            out SafeFwpmMemoryBuffer entries, // FWPM_CALLOUT0*** 
            out int numEntriesReturned
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmCalloutGetByKey0(
          SafeFwpmEngineHandle engineHandle,
          in Guid key,
          out SafeFwpmMemoryBuffer callout //  FWPM_CALLOUT0 **
        );

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern Win32Error FwpmCalloutDestroyEnumHandle0(
            SafeFwpmEngineHandle engineHandle,
            IntPtr enumHandle
        );
    }
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member