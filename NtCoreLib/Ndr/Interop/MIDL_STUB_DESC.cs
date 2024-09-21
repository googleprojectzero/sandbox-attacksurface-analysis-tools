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

using NtCoreLib.Utilities.Memory;
using System;
using System.Runtime.InteropServices;

namespace NtCoreLib.Ndr.Interop;

[StructLayout(LayoutKind.Sequential)]
internal struct MIDL_STUB_DESC : IConvertToNative<MIDL_STUB_DESC>
{
    public IntPtr RpcInterfaceInformation;
    public IntPtr pfnAllocate;
    public IntPtr pfnFree;
    public IntPtr pGenericBindingInfo;
    public IntPtr apfnNdrRundownRoutines;
    public IntPtr aGenericBindingRoutinePairs;
    public IntPtr apfnExprEval;
    public IntPtr aXmitQuintuple;
    public IntPtr pFormatTypes;
    public int fCheckBounds;
    /* Ndr library version. */
    public int Version;
    public IntPtr pMallocFreeStruct;
    public int MIDLVersion;
    public IntPtr CommFaultOffsets;
    // New fields for version 3.0+
    public IntPtr aUserMarshalQuadruple;
    // Notify routines - added for NT5, MIDL 5.0
    public IntPtr NotifyRoutineTable;
    public IntPtr mFlags;
    // International support routines - added for 64bit post NT5
    public IntPtr CsRoutineTables;
    public IntPtr ProxyServerInfo;
    public IntPtr pExprInfo;

    public NDR_EXPR_DESC GetExprDesc(IMemoryReader reader)
    {
        if (pExprInfo != IntPtr.Zero)
        {
            return reader.ReadStruct<NDR_EXPR_DESC>(pExprInfo);
        }
        return new NDR_EXPR_DESC();
    }

    public RpcFlags GetFlags()
    {
        return (RpcFlags)(uint)mFlags.ToInt32();
    }

    MIDL_STUB_DESC IConvertToNative<MIDL_STUB_DESC>.Read(IMemoryReader reader, IntPtr address, int index)
    {
        return reader.ReadStruct<MIDL_STUB_DESC32>(address, index).Convert();
    }
}
