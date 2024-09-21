//  Copyright 2020 Google Inc. All Rights Reserved.
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

using System.Collections.Generic;
using System.IO;

namespace NtApiDotNet.Utilities.ASN1
{
    /// <summary>
    /// A basic ASN.1 DER parser to process Kerberos and SPNEGO Tokens.
    /// </summary>
    internal class DERParser
    {
        private static DERValue[] ParseData(long offset, byte[] data, int index)
        {
            DERParserStream stm = new DERParserStream(data, index, data.Length - index, offset);
            List<DERValue> values = new List<DERValue>();
            while (!stm.Done)
            {
                DERValue v = stm.ReadValue();
                if (v.Constructed)
                {
                    v.Children = ParseData(v.DataOffset, v.Data, 0);
                }
                values.Add(v);
            }
            return values.ToArray();
        }

        public static DERValue[] ParseData(byte[] data, int index = 0)
        {
            return ParseData(0, data, index);
        }

        public static DERValue[] ParseFile(string path)
        {
            return ParseData(File.ReadAllBytes(path), 0);
        }
    }
}
