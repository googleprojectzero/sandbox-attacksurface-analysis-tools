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
    #region Marshal Helpers
    internal class _Unmarshal_Helper : NdrUnmarshalBuffer
    {
        public _Unmarshal_Helper(byte[] ba) :
                base(ba)
        {
        }
        public RpcExtendedErrorInfoInternal Read_0()
        {
            return ReadStruct<RpcExtendedErrorInfoInternal>();
        }
        public ExtendedErrorInfoParamInternal Read_1()
        {
            return ReadStruct<ExtendedErrorInfoParamInternal>();
        }
        public Union_2 Read_2()
        {
            return ReadStruct<Union_2>();
        }
        public AnsiStringData Read_3()
        {
            return ReadStruct<AnsiStringData>();
        }
        public UnicodeStringData Read_4()
        {
            return ReadStruct<UnicodeStringData>();
        }
        public BinaryData Read_5()
        {
            return ReadStruct<BinaryData>();
        }
        public ComputerNameData Read_7()
        {
            return ReadStruct<ComputerNameData>();
        }
        public byte[] Read_9()
        {
            return ReadConformantArray<byte>();
        }
        public short[] Read_10()
        {
            return ReadConformantArray<short>();
        }
        public sbyte[] Read_11()
        {
            return ReadConformantArray<sbyte>();
        }
    }
    #endregion
    #region Complex Types
    internal struct RpcExtendedErrorInfoInternal : INdrStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            throw new NotImplementedException();
        }

        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            int max_count = u.ReadInt32();
            u.Align(8);
            Chain = u.ReadEmbeddedPointer(new Func<RpcExtendedErrorInfoInternal>(u.Read_0));
            ComputerName = u.ReadStruct<ComputerNameUnion>();
            ProcessId = u.ReadInt32();
            TimeStamp = u.ReadInt64();
            GeneratingComponent = u.ReadInt32();
            Status = u.ReadInt32();
            DetectionLocation = u.ReadInt16();
            Flags = u.ReadInt16();
            nLen = u.ReadInt16();
            Parameters = u.ReadFixedStructArray<ExtendedErrorInfoParamInternal>(max_count);
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
            Unmarshal((_Unmarshal_Helper)u);
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            u.Align(8);
            ParameterType = u.ReadEnum16();
            ParameterData = u.Read_2();
        }
        public NdrEnum16 ParameterType;
        public Union_2 ParameterData;

        public object GetObject()
        {
            switch (ParameterType)
            {
                case 1:
                    return ParameterData.AnsiString.GetString();
                case 2:
                    return ParameterData.UnicodeString.GetString();
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
    internal struct Union_2 : INdrNonEncapsulatedUnion
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
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            u.Align(1);
            Selector = u.ReadInt16();
            if ((Selector == 1))
            {
                AnsiString = u.Read_3();
                goto done;
            }
            if ((Selector == 2))
            {
                UnicodeString = u.Read_4();
                goto done;
            }
            if ((Selector == 3))
            {
                LongVal = u.ReadInt32();
                goto done;
            }
            if ((Selector == 4))
            {
                ShortVal = u.ReadInt16();
                goto done;
            }
            if ((Selector == 5))
            {
                PointerVal = u.ReadInt64();
                goto done;
            }
            if ((Selector == 6))
            {
                NoneVal = u.ReadEmpty();
                goto done;
            }
            if ((Selector == 7))
            {
                BinaryVal = u.Read_5();
                goto done;
            }
            throw new System.ArgumentException("No matching union selector when marshaling Union_2");
            done:
            return;
        }
        private short Selector;
        public AnsiStringData AnsiString;
        public UnicodeStringData UnicodeString;
        public int LongVal;
        public short ShortVal;
        public long PointerVal;
        public NdrEmpty NoneVal;
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
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            u.Align(4);
            Length = u.ReadInt16();
            Data = u.ReadEmbeddedPointer(new Func<byte[]>(u.Read_9));
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
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            u.Align(4);
            Length = u.ReadInt16();
            Data = u.ReadEmbeddedPointer<short[]>(new Func<short[]>(u.Read_10));
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
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            u.Align(4);
            Length = u.ReadInt16();
            Data = u.ReadEmbeddedPointer<sbyte[]>(new System.Func<sbyte[]>(u.Read_11));
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
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            u.Align(4);
            Member0 = u.ReadEnum16();
            Member8 = u.Read_7();
        }
        public NdrEnum16 Member0;
        public ComputerNameData Member8;

        public string GetString()
        {
            if (Member0 == 1)
            {
                return Member8.Arm_1.GetString();
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
            Unmarshal((_Unmarshal_Helper)u);
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            u.Align(1);
            Selector = u.ReadInt16();
            if ((Selector == 1))
            {
                Arm_1 = u.Read_4();
                goto done;
            }
            if ((Selector == 2))
            {
                Arm_2 = u.ReadEmpty();
                goto done;
            }
            throw new System.ArgumentException("No matching union selector when marshaling ComputerNameData");
            done:
            return;
        }
        private short Selector;
        public UnicodeStringData Arm_1;
        public NdrEmpty Arm_2;
    }
    #endregion
    #region Complex Type Encoders
    internal static class ExtendedErrorInfoDecoder
    {
        internal static RpcExtendedErrorInfoInternal? Decode(byte[] data)
        {
            _Unmarshal_Helper u = new _Unmarshal_Helper(data);
            RpcExtendedErrorInfoInternal v;
            // Read out referent.
            int referent = u.ReadReferent();
            if (referent == 0)
            {
                return null;
            }
            v = u.Read_0();
            u.PopulateDeferredPointers();
            return v;
        }
    }
    #endregion

}
