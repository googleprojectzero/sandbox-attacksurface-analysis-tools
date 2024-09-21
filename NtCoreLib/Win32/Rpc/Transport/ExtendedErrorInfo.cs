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
    internal struct ExtendedErrorInfo : INdrConformantStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            throw new NotImplementedException();
        }

        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            Next = u.ReadEmbeddedPointer(u.ReadStruct<ExtendedErrorInfo>, false);
            ComputerName = u.ReadStruct<EEComputerName>();
            ProcessId = u.ReadInt32();
            TimeStamp = u.ReadInt64();
            GeneratingComponent = u.ReadInt32();
            Status = u.ReadInt32();
            DetectionLocation = u.ReadInt16();
            Flags = u.ReadInt16();
            nLen = u.ReadInt16();
            Params = u.ReadConformantStructArray<ExtendedErrorInfoParamInternal>();
        }

        int INdrStructure.GetAlignment()
        {
            return 8;
        }

        int INdrConformantStructure.GetConformantDimensions()
        {
            return 1;
        }

        public NdrEmbeddedPointer<ExtendedErrorInfo> Next;
        public EEComputerName ComputerName;
        public int ProcessId;
        public long TimeStamp;
        public int GeneratingComponent;
        public int Status;
        public short DetectionLocation;
        public short Flags;
        public short nLen;
        public ExtendedErrorInfoParamInternal[] Params;
    }
    internal struct ExtendedErrorInfoParamInternal : INdrStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            throw new NotImplementedException();
        }

        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            ParameterType = u.ReadEnum16();
            ParameterData = u.ReadStruct<ParameterValueUnion>();
        }

        int INdrStructure.GetAlignment()
        {
            return 8;
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
                    return ParameterData.LVal;
                case 4:
                    return ParameterData.IVal;
                case 5:
                    return ParameterData.PVal;
                case 7:
                    return ParameterData.Blob.GetObject();
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
            switch (u.ReadInt16())
            {
                case 1:
                    AnsiString = u.ReadStruct<EEAString>();
                    break;
                case 2:
                    UnicodeString = u.ReadStruct<EEUString>();
                    break;
                case 3:
                    LVal = u.ReadInt32();
                    break;
                case 4:
                    IVal = u.ReadInt16();
                    break;
                case 5:
                    PVal = u.ReadInt64();
                    break;
                case 6:
                    break;
                case 7:
                    Blob = u.ReadStruct<BinaryEEInfo>();
                    break;
                default:
                    throw new System.ArgumentException("No matching union selector when marshaling Union_2");
            }
        }

        int INdrStructure.GetAlignment()
        {
            return 1;
        }

        public EEAString AnsiString;
        public EEUString UnicodeString;
        public int LVal;
        public short IVal;
        public long PVal;
        public BinaryEEInfo Blob;
    }
    internal struct EEAString : INdrStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            throw new NotImplementedException();
        }
        
        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            nLength = u.ReadInt16();
            pString = u.ReadEmbeddedPointer(u.ReadConformantArray<byte>, false);
        }

        int INdrStructure.GetAlignment()
        {
            return 4;
        }

        public short nLength;
        public NdrEmbeddedPointer<byte[]> pString;

        public string GetString()
        {
            return BinaryEncoding.Instance.GetString(pString.GetValue());
        }
    }
    internal struct EEUString : INdrStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            throw new NotImplementedException();
        }

        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            nLength = u.ReadInt16();
            pString = u.ReadEmbeddedPointer(u.ReadConformantArray<short>, false);
        }

        int INdrStructure.GetAlignment()
        {
            return 4;
        }

        public short nLength;
        public NdrEmbeddedPointer<short[]> pString;

        public string GetString()
        {
            short[] data = pString.GetValue();
            byte[] buffer = new byte[data.Length * 2];
            Buffer.BlockCopy(data, 0, buffer, 0, buffer.Length);
            return Encoding.Unicode.GetString(buffer);
        }
    }

    internal struct BinaryEEInfo : INdrStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            throw new NotImplementedException();
        }

        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            nSize = u.ReadInt16();
            pBlob = u.ReadEmbeddedPointer(u.ReadConformantArray<sbyte>, false);
        }

        int INdrStructure.GetAlignment()
        {
            return 4;
        }

        public short nSize;
        public NdrEmbeddedPointer<sbyte[]> pBlob;

        public object GetObject()
        {
            return (byte[])(object)pBlob.GetValue();
        }
    }
    internal struct EEComputerName : INdrStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            throw new NotImplementedException();
        }

        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            Selector = u.ReadEnum16();
            Name = u.ReadStruct<EEComputerNameData>();
        }

        int INdrStructure.GetAlignment()
        {
            return 4;
        }

        public NdrEnum16 Selector;
        public EEComputerNameData Name;

        public string GetString()
        {
            if (Selector == 1)
            {
                return Name.StringData.GetString();
            }
            return string.Empty;
        }
    }
    internal struct EEComputerNameData : INdrNonEncapsulatedUnion
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
            switch (u.ReadInt16())
            {
                case 1:
                    StringData = u.ReadStruct<EEUString>();
                    break;
                case 2:
                    break;
                default:
                    throw new System.ArgumentException("No matching union selector when marshaling ComputerNameData");
            }
        }

        int INdrStructure.GetAlignment()
        {
            return 1;
        }

        public EEUString StringData;
    }
    #endregion
    #region Complex Type Encoders
    internal static class ExtendedErrorInfoDecoder
    {
        internal static ExtendedErrorInfo? Decode(byte[] data)
        {
            NdrPickledType pickled_type = new NdrPickledType(data);
            NdrUnmarshalBuffer u = new NdrUnmarshalBuffer(pickled_type);
            var res = u.ReadReferentValue(u.ReadStruct<ExtendedErrorInfo>, false);
            return res;
        }
    }
    #endregion

}
