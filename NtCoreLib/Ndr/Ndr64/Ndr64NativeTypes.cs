//  Copyright 2023 Google LLC. All Rights Reserved.
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

using NtCoreLib.Security.Authorization;
using System;
using System.Runtime.InteropServices;

namespace NtCoreLib.Ndr.Ndr64;

enum NDR64_HANDLE_TYPE
{
    NDR64_FC_EXPLICIT_HANDLE = 0,
    NDR64_FC_BIND_GENERIC = 1,
    NDR64_FC_BIND_PRIMITIVE = 2,
    NDR64_FC_AUTO_HANDLE = 3,
    NDR64_FC_CALLBACK_HANDLE = 4,
    NDR64_FC_NO_HANDLE = 5,
}

[StructLayout(LayoutKind.Sequential)]
internal readonly struct NDR64_PROC_FLAGS
{
    private readonly int Value;

    public NDR64_HANDLE_TYPE HandleType => (NDR64_HANDLE_TYPE)Value.GetBits(0, 3);
    public int ProcType => Value.GetBits(3, 3);
    public int IsInterpreted => Value.GetBits(6, 2);
    public bool IsObject => Value.GetBit(8);
    public bool IsAsync => Value.GetBit(9);
    public bool IsEncode => Value.GetBit(10);
    public bool IsDecode => Value.GetBit(11);
    public bool UsesFullPtrPackage => Value.GetBit(12);
    public bool UsesRpcSmPackage => Value.GetBit(13);
    public bool UsesPipes => Value.GetBit(14);
    public int HandlesExceptions => Value.GetBits(15, 2);
    public bool ServerMustSize => Value.GetBit(17);
    public bool ClientMustSize => Value.GetBit(18);
    public bool HasReturn => Value.GetBit(19);
    public bool HasComplexReturn => Value.GetBit(20);
    public bool ServerHasCorrelation => Value.GetBit(21);
    public bool ClientHasCorrelation => Value.GetBit(22);
    public bool HasNotify => Value.GetBit(23);
    public bool HasOtherExtensions => Value.GetBit(24);
    public bool HasBigByValueParam => Value.GetBit(25);
    public bool HasArmParamLayout => Value.GetBit(25);
    // int Reserved : 5;
};

[StructLayout(LayoutKind.Sequential)]
internal readonly struct NDR64_RPC_FLAGS
{
    private readonly ushort Value;

    public bool Idempotent => Value.GetBit(0);
    public bool Broadcast => Value.GetBit(1);
    public bool Maybe => Value.GetBit(2);
    // ushort Reserved0 : 1
    public bool HasGuarantee => Value.GetBit(4);
    //ushort Reserved1 : 3;
    public bool Message => Value.GetBit(8);
    //ushort Reserved2 : 4;
    public bool InputSynchronous => Value.GetBit(13);
    public bool Asynchronous => Value.GetBit(14);
    public bool WinrtRemoteAsync => Value.GetBit(15);
};

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_PROC_FORMAT
{
    public NDR64_PROC_FLAGS Flags;
    public int StackSize;
    public int ConstantClientBufferSize;
    public int ConstantServerBufferSize;
    public NDR64_RPC_FLAGS RpcFlags;
    public ushort FloatDoubleMask;
    public ushort NumberOfParams;
    public ushort ExtensionSize;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_PARAM_FORMAT
{
    public IntPtr /* PNDR64_FORMAT */ Type;
    public Ndr64ParamFlags Attributes;
    public ushort Reserved;
    public int StackOffset;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_RANGE_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public Ndr64FormatCharacter RangeType;
    public ushort Reserved;
    public long MinValue;
    public long MaxValue;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_CONTEXT_HANDLE_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public Ndr64ContextHandleFlags ContextFlags;
    public byte RundownRoutineIndex;
    public byte Ordinal;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_BIND_PRIMITIVE
{
    public Ndr64FormatCharacter HandleType;
    public Ndr64ContextHandleFlags Flags;
    public ushort StackOffset;
    public ushort Reserved;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_BIND_GENERIC
{
    public Ndr64FormatCharacter HandleType;
    public Ndr64ContextHandleFlags Flags;
    public ushort StackOffset;
    public byte RoutineIndex;
    public byte Size;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_BIND_CONTEXT
{
    public Ndr64FormatCharacter HandleType;
    public Ndr64ContextHandleFlags Flags;
    public ushort StackOffset;
    public byte RoutineIndex;
    public byte Ordinal;
}

//typedef union _NDR64_BINDINGS {
//  NDR64_BIND_PRIMITIVE Primitive;
//NDR64_BIND_GENERIC Generic;
//NDR64_BIND_CONTEXT Context;
//} NDR64_BINDINGS;

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_BIND_AND_NOTIFY_EXTENSION
{
    public NDR64_BIND_CONTEXT Binding;
    public ushort NotifyIndex;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_POINTER_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public Ndr64PointerFlags Flags;
    public ushort Reserved;
    public IntPtr /* PNDR64_FORMAT */ Pointee;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_NO_REPEAT_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public byte Flags;
    public ushort Reserved1;
    public uint Reserved2;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_POINTER_INSTANCE_HEADER_FORMAT
{
    public uint Offset;
    public uint Reserved;
}

enum NDR64_POINTER_REPEAT_FLAGS : byte
{
    SetCorrMark = 0x1,
    Reserved = 0xFE,
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_REPEAT_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public NDR64_POINTER_REPEAT_FLAGS Flags;
    public ushort Reserved;
    public uint Increment;
    public uint OffsetToArray;
    public uint NumberOfPointers;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_FIXED_REPEAT_FORMAT
{
    public NDR64_REPEAT_FORMAT RepeatFormat;
    public uint Iterations;
    public uint Reserved;
}

enum NDR64_IID_FLAGS : byte
{
    ConstantIID = 0x1,
    Reserved = 0xFE
};

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_CONSTANT_IID_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public NDR64_IID_FLAGS Flags;
    public ushort Reserved;
    public Guid Guid;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_IID_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public NDR64_IID_FLAGS Flags;
    public ushort Reserved;
    public IntPtr /* PNDR64_FORMAT */ IIDDescriptor;
}

[Flags]
enum NDR64_STRUCTURE_FLAGS : byte
{
    HasPointerInfo = 0x1,
    HasMemberInfo = 0x2,
    HasConfArray = 0x4,
    HasOrigPointerInfo = 0x8,
    HasOrigMemberInfo = 0x10,
    Reserved1 = 0x20,
    Reserved2 = 0x40,
    Reserved3 = 0x80
};

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_STRUCTURE_HEADER_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public byte /* NDR64_ALIGNMENT */ Alignment;
    public NDR64_STRUCTURE_FLAGS Flags;
    public byte Reserve;
    public uint MemorySize;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_CONF_STRUCTURE_HEADER_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public byte /* NDR64_ALIGNMENT */ Alignment;
    public NDR64_STRUCTURE_FLAGS Flags;
    public byte Reserve;
    public uint MemorySize;
    public IntPtr /* PNDR64_FORMAT */ ArrayDescription;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_BOGUS_STRUCTURE_HEADER_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public byte /* NDR64_ALIGNMENT */ Alignment;
    public NDR64_STRUCTURE_FLAGS Flags;
    public byte Reserve;
    public uint MemorySize;
    public IntPtr /* PNDR64_FORMAT */ OriginalMemberLayout;
    public IntPtr /* PNDR64_FORMAT */ OriginalPointerLayout;
    public IntPtr /* PNDR64_FORMAT */ PointerLayout;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_CONF_BOGUS_STRUCTURE_HEADER_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public byte /* NDR64_ALIGNMENT */ Alignment;
    public NDR64_STRUCTURE_FLAGS Flags;
    public byte Dimensions;
    public uint MemorySize;
    public IntPtr /* PNDR64_FORMAT */ OriginalMemberLayout;
    public IntPtr /* PNDR64_FORMAT */ OriginalPointerLayout;
    public IntPtr /* PNDR64_FORMAT */ PointerLayout;
    public IntPtr /* PNDR64_FORMAT */ ConfArrayDescription;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_SIMPLE_MEMBER_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public byte Reserved1;
    public ushort Reserved2;
    public uint Reserved3;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_MEMPAD_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public byte Reserve1;
    public ushort MemPad;
    public uint Reserved2;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_EMBEDDED_COMPLEX_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public byte Reserve1;
    public ushort Reserve2;
    public IntPtr /* PNDR64_FORMAT */ Type;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_BUFFER_ALIGN_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public byte /* NDR64_ALIGNMENT */ Alignment;
    public ushort Reserved;
    public uint Reserved2;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_SIMPLE_REGION_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public byte /* NDR64_ALIGNMENT */ Alignment;
    public ushort RegionSize;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_ENCAPSULATED_UNION
{
    public Ndr64FormatCharacter FormatCode;
    public byte Alignment;
    public byte Flags;
    public Ndr64FormatCharacter SwitchType;
    public uint MemoryOffset;
    public uint MemorySize;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_NON_ENCAPSULATED_UNION
{
    public Ndr64FormatCharacter FormatCode;
    public byte Alignment;
    public byte Flags;
    public Ndr64FormatCharacter SwitchType;
    public uint MemorySize;
    public IntPtr /* PNDR64_FORMAT */ Switch;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_UNION_ARM_SELECTOR
{
    public byte Reserved1;
    public byte Alignment;
    public ushort Reserved2;
    public uint Arms;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_UNION_ARM
{
    public long CaseValue;
    public IntPtr /* PNDR64_FORMAT */ Type;
    public uint Reserved;
}

[Flags]
enum NDR64_ARRAY_FLAGS : byte
{
    HasPointerInfo = 0x1,
    HasElementInfo = 0x2,
    IsMultiDimensional = 0x4,
    IsArrayofStrings = 0x8,
    Reserved1 = 0x10,
    Reserved2 = 0x20,
    Reserved3 = 0x40,
    Reserved4 = 0x80
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_ARRAY_ELEMENT_INFO
{
    public uint ElementMemSize;
    public IntPtr /* PNDR64_FORMAT */ Element;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_FIX_ARRAY_HEADER_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public byte /* NDR64_ALIGNMENT */ Alignment;
    public NDR64_ARRAY_FLAGS Flags;
    public byte Reserved;
    public int TotalSize;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_CONF_ARRAY_HEADER_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public byte /* NDR64_ALIGNMENT */ Alignment;
    public NDR64_ARRAY_FLAGS Flags;
    public byte Reserved;
    public uint ElementSize;
    public IntPtr /* PNDR64_FORMAT */ ConfDescriptor;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_CONF_VAR_ARRAY_HEADER_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public byte /* NDR64_ALIGNMENT */ Alignment;
    public NDR64_ARRAY_FLAGS Flags;
    public byte Reserved;
    public uint ElementSize;
    public IntPtr /* PNDR64_FORMAT */ ConfDescriptor;
    public IntPtr /* PNDR64_FORMAT */ VarDescriptor;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_VAR_ARRAY_HEADER_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public byte /* NDR64_ALIGNMENT */ Alignment;
    public NDR64_ARRAY_FLAGS Flags;
    public byte Reserved;
    public uint TotalSize;
    public uint ElementSize;
    public IntPtr /* PNDR64_FORMAT */ VarDescriptor;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_BOGUS_ARRAY_HEADER_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public byte /* NDR64_ALIGNMENT */ Alignment;
    public NDR64_ARRAY_FLAGS Flags;
    public byte NumberDims;
    public uint NumberElements;
    public IntPtr /* PNDR64_FORMAT */ Element;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_CONF_VAR_BOGUS_ARRAY_HEADER_FORMAT
{
    public NDR64_BOGUS_ARRAY_HEADER_FORMAT FixedArrayFormat;
    public IntPtr /* PNDR64_FORMAT */ ConfDescription;
    public IntPtr /* PNDR64_FORMAT */ VarDescription;
    public IntPtr /* PNDR64_FORMAT */ OffsetDescription;
}

[Flags]
enum NDR64_STRING_FLAGS : byte
{
    IsSized = 0x1,
    Reserved2 = 0x2,
    Reserved3 = 0x4,
    Reserved4 = 0x8,
    Reserved5 = 0x10,
    Reserved6 = 0x20,
    Reserved7 = 0x40,
    Reserved8 = 0x80
};

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_STRING_HEADER_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public NDR64_STRING_FLAGS Flags;
    public ushort ElementSize;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_NON_CONFORMANT_STRING_FORMAT
{
    public NDR64_STRING_HEADER_FORMAT Header;
    public uint TotalSize;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_CONFORMANT_STRING_FORMAT
{
    public NDR64_STRING_HEADER_FORMAT Header;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_SIZED_CONFORMANT_STRING_FORMAT
{
    public NDR64_STRING_HEADER_FORMAT Header;
    public IntPtr /* PNDR64_FORMAT */ SizeDescription;
}

enum NDR64_EXPR_TOKEN : byte
{
    FC_EXPR_START = 0, 
    FC_EXPR_ILLEGAL = FC_EXPR_START, 
    FC_EXPR_CONST32, 
    FC_EXPR_CONST64, 
    FC_EXPR_VAR, 
    FC_EXPR_OPER, 
    FC_EXPR_NOOP, 
    FC_EXPR_END
}

enum NDR64_OPERATOR_TYPE : byte
{
    OP_UNARY_PLUS = 0x01,
    OP_UNARY_MINUS = 0x02,
    OP_UNARY_NOT = 0x03,
    OP_UNARY_COMPLEMENT = 0x04,
    OP_UNARY_INDIRECTION = 0x05,
    OP_UNARY_CAST = 0x06,
    OP_UNARY_AND = 0x07,
    OP_UNARY_SIZEOF = 0x08,
    OP_UNARY_ALIGNOF = 0x09,
    OP_PRE_INCR = 0x0a,
    OP_PRE_DECR = 0x0b,
    OP_POST_INCR = 0x0c,
    OP_POST_DECR = 0x0d,
    OP_PLUS = 0x0e,
    OP_MINUS = 0x0f,
    OP_STAR = 0x10,
    OP_SLASH = 0x11,
    OP_MOD = 0x12,
    OP_LEFT_SHIFT = 0x13,
    OP_RIGHT_SHIFT = 0x14,
    OP_LESS = 0x15,
    OP_LESS_EQUAL = 0x16,
    OP_GREATER_EQUAL = 0x17,
    OP_GREATER = 0x18,
    OP_EQUAL = 0x19,
    OP_NOT_EQUAL = 0x1A,
    OP_AND = 0x1B,
    OP_OR = 0x1C,
    OP_XOR = 0x1D,
    OP_LOGICAL_AND = 0x1E,
    OP_LOGICAL_OR = 0x1F,
    OP_EXPRESSION = 0x20,
    OP_ASYNCSPLIT = 0x2B,
    OP_CORR_POINTER = 0x2C,
    OP_CORR_TOP_LEVEL = 0x2D,
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_EXPR_OPERATOR
{
    public NDR64_EXPR_TOKEN ExprType;
    public NDR64_OPERATOR_TYPE Operator;
    public Ndr64FormatCharacter CastType;
    public byte Reserved;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_EXPR_CONST32
{
    public NDR64_EXPR_TOKEN ExprType;
    public Ndr64FormatCharacter Reserved;
    public ushort Reserved1;
    public uint ConstValue;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_EXPR_CONST64
{
    public NDR64_EXPR_TOKEN ExprType;
    public Ndr64FormatCharacter Reserved;
    public ushort Reserved1;
    public long ConstValue;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_EXPR_VAR
{
    public NDR64_EXPR_TOKEN ExprType;
    public Ndr64FormatCharacter VarType;
    public ushort Reserved;
    public uint Offset;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_EXPR_NOOP
{
    public Ndr64FormatCharacter ExprType;
    public byte Size;
    public ushort Reserved;
}

[Flags]
enum NDR64_TRANSMIT_AS_FLAGS : byte
{
    PresentedTypeIsArray = 0x1,
    PresentedTypeAlign4 = 0x2,
    PresentedTypeAlign8 = 0x4,
    Reserved = 0xF8
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_TRANSMIT_AS_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public NDR64_TRANSMIT_AS_FLAGS Flags;
    public ushort RoutineIndex;
    public ushort TransmittedTypeWireAlignment;
    public ushort MemoryAlignment;
    public uint PresentedTypeMemorySize;
    public uint TransmittedTypeBufferSize;
    public IntPtr /* PNDR64_FORMAT */ TransmittedType;
}

[Flags]
enum NDR64_USER_MARSHAL_FLAGS : byte
{
    Reserved = 0x1F,
    IID = 0x20,
    RefPointer = 0x40,
    UniquePointer = 0x80
};

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_USER_MARSHAL_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public NDR64_USER_MARSHAL_FLAGS Flags;
    public ushort RoutineIndex;
    public ushort TransmittedTypeWireAlignment;
    public ushort MemoryAlignment;
    public uint UserTypeMemorySize;
    public uint TransmittedTypeBufferSize;
    public IntPtr /* PNDR64_FORMAT */ TransmittedType;
}

[Flags]
enum NDR64_PIPE_FLAGS : byte
{
    Reserved1 = 0x1F,
    HasRange = 0x20,
    BlockCopy = 0x40,
    Reserved2 = 0x80
};

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_PIPE_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public NDR64_PIPE_FLAGS Flags;
    public byte Alignment;
    public byte Reserved;
    public IntPtr /* PNDR64_FORMAT */ Type;
    public uint MemorySize;
    public uint BufferSize;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_RANGE_PIPE_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public NDR64_PIPE_FLAGS Flags;
    public byte Alignment;
    public byte Reserved;
    public IntPtr /* PNDR64_FORMAT */ Type;
    public uint MemorySize;
    public uint BufferSize;
    public uint MinValue;
    public uint MaxValue;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_SYSTEM_HANDLE_FORMAT
{
    public Ndr64FormatCharacter FormatCode;
    public byte HandleType;
    public AccessMask DesiredAccess;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
internal struct NDR64_TYPE_STRICT_CONTEXT_HANDLE
{
  public Ndr64FormatCharacter FormatCode;
  public Ndr64FormatCharacter RealFormatCode;
  public ushort Reserved;
  public IntPtr Type;
  public int CtxtFlags;
  public int CtxtID;
}
