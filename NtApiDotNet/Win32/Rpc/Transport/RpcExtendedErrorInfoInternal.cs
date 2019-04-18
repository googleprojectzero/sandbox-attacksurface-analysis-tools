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

using NtApiDotNet.Ndr.Marshal;
using NtApiDotNet.Utilities.Text;
using System;
using System.Text;

namespace NtApiDotNet.Win32.Rpc.Transport
{
    #region Complex Types
    internal struct RpcExtendedErrorInfoInternal : INdrConformantStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            throw new NotImplementedException();
        }

        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            u.Align(8);
            Chain = u.ReadEmbeddedPointer(u.ReadStruct<RpcExtendedErrorInfoInternal>, false);
            ComputerName = u.ReadStruct<ComputerNameUnion>();
            ProcessId = u.ReadInt32();
            TimeStamp = u.ReadInt64();
            GeneratingComponent = u.ReadInt32();
            Status = u.ReadInt32();
            DetectionLocation = u.ReadInt16();
            Flags = u.ReadInt16();
            nLen = u.ReadInt16();
            Parameters = u.ReadConformantStructArray<ExtendedErrorInfoParamInternal>();
        }

        int INdrConformantStructure.GetConformantDimensions()
        {
            return 1;
        }

        public NdrEmbeddedPointer<RpcExtendedErrorInfoInternal> Chain;
        public ComputerNameUnion ComputerName;
        public int ProcessId;
        public long TimeStamp;
        public int GeneratingComponent;
        public int Status;
        public short DetectionLocation;
        public short Flags;
        public short nLen;
        public ExtendedErrorInfoParamInternal[] Parameters;
    }
    internal struct ExtendedErrorInfoParamInternal : INdrStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            throw new NotImplementedException();
        }

        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            u.Align(8);
            ParameterType = u.ReadEnum16();
            ParameterData = u.ReadStruct<ParameterValueUnion>();
        }

        public NdrEnum16 ParameterType;
        public ParameterValueUnion ParameterData;

        public object GetObject()
        {
            switch (ParameterType)
            {
                case 1:
                    return ParameterData.AnsiString.GetString().TrimEnd('\0');
                case 2:
                    return ParameterData.UnicodeString.GetString().TrimEnd('\0');
                case 3:
                    return ParameterData.LongVal;
                case 4:
                    return ParameterData.ShortVal;
                case 5:
                    return ParameterData.PointerVal;
                case 7:
                    return ParameterData.BinaryVal.GetObject();
                default:
                    return string.Empty;
            }
        }
    }
    internal struct ParameterValueUnion : INdrStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            throw new NotImplementedException();
        }

        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            u.Align(1);

            switch (u.ReadInt16())
            {
                case 1:
                    AnsiString = u.ReadStruct<AnsiStringData>();
                    break;
                case 2:
                    UnicodeString = u.ReadStruct<UnicodeStringData>();
                    break;
                case 3:
                    LongVal = u.ReadInt32();
                    break;
                case 4:
                    ShortVal = u.ReadInt16();
                    break;
                case 5:
                    PointerVal = u.ReadInt64();
                    break;
                case 6:
                    break;
                case 7:
                    BinaryVal = u.ReadStruct<BinaryData>();
                    break;
                default:
                    throw new System.ArgumentException("No matching union selector when marshaling Union_2");
            }
        }

        public AnsiStringData AnsiString;
        public UnicodeStringData UnicodeString;
        public int LongVal;
        public short ShortVal;
        public long PointerVal;
        public BinaryData BinaryVal;
    }
    internal struct AnsiStringData : INdrStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            throw new NotImplementedException();
        }
        
        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            u.Align(4);
            Length = u.ReadInt16();
            Data = u.ReadEmbeddedPointer(u.ReadConformantArray<byte>, false);
        }

        public short Length;
        public NdrEmbeddedPointer<byte[]> Data;

        public string GetString()
        {
            return BinaryEncoding.Instance.GetString(Data.GetValue());
        }
    }
    internal struct UnicodeStringData : INdrStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            throw new NotImplementedException();
        }

        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            u.Align(4);
            Length = u.ReadInt16();
            Data = u.ReadEmbeddedPointer(u.ReadConformantArray<short>, false);
        }

        public short Length;
        public NdrEmbeddedPointer<short[]> Data;

        public string GetString()
        {
            short[] data = Data.GetValue();
            byte[] buffer = new byte[data.Length * 2];
            Buffer.BlockCopy(data, 0, buffer, 0, buffer.Length);
            return Encoding.Unicode.GetString(buffer);
        }
    }

    internal struct BinaryData : INdrStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            throw new NotImplementedException();
        }

        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            u.Align(4);
            Length = u.ReadInt16();
            Data = u.ReadEmbeddedPointer(u.ReadConformantArray<sbyte>, false);
        }

        public short Length;
        public NdrEmbeddedPointer<sbyte[]> Data;

        public object GetObject()
        {
            return (byte[])(object)Data.GetValue();
        }
    }
    internal struct ComputerNameUnion : INdrStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            throw new NotImplementedException();
        }

        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            u.Align(4);
            Selector = u.ReadEnum16();
            Name = u.ReadStruct<ComputerNameData>();
        }

        public NdrEnum16 Selector;
        public ComputerNameData Name;

        public string GetString()
        {
            if (Selector == 1)
            {
                return Name.StringData.GetString();
            }
            return string.Empty;
        }
    }
    internal struct ComputerNameData : INdrNonEncapsulatedUnion
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            throw new NotImplementedException();
        }
        void INdrNonEncapsulatedUnion.Marshal(NdrMarshalBuffer m, long l)
        {
            throw new NotImplementedException();
        }

        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            u.Align(1);
            switch (u.ReadInt16())
            {
                case 1:
                    StringData = u.ReadStruct<UnicodeStringData>();
                    break;
                case 2:
                    break;
                default:
                    throw new System.ArgumentException("No matching union selector when marshaling ComputerNameData");
            }
        }

        public UnicodeStringData StringData;
    }
    #endregion
    #region Complex Type Encoders
    internal static class ExtendedErrorInfoDecoder
    {
        internal static RpcExtendedErrorInfoInternal? Decode(byte[] data)
        {
            NdrUnmarshalBuffer u = new NdrUnmarshalBuffer(data);
            var res = u.ReadReferentValue(u.ReadStruct<RpcExtendedErrorInfoInternal>, false);
            u.PopulateDeferredPointers();
            return res;
        }
    }
    #endregion

}
