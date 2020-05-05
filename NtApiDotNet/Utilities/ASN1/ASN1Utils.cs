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
using System.Text;

namespace NtApiDotNet.Utilities.ASN1
{
    /// <summary>
    /// Basic utilities for ASN1 support.
    /// </summary>
    public static class ASN1Utils
    {
        private static void DumpValue(StringBuilder builder, DERValue v, int depth)
        {
            builder.AppendFormat("{0} {1:X}/{1} {2} {3} {4} {5:X}", new string(' ', depth * 2), 
                v.Offset, v.Type, v.Constructed, v.FormatTag(), v.FormatValue());
            builder.AppendLine();

            if (v.Children != null)
            {
                foreach (var c in v.Children)
                {
                    DumpValue(builder, c, depth + 1);
                }
            }
        }

        internal static string FormatDER(IEnumerable<DERValue> values, int depth)
        {
            StringBuilder builder = new StringBuilder();
            foreach (var v in values)
            {
                DumpValue(builder, v, depth);
            }
            return builder.ToString();
        }

        /// <summary>
        /// Format an array of ASN.1 DER to a string.
        /// </summary>
        /// <param name="asn1_der">The ASN.1 data in DER format.</param>
        /// <param name="depth">Initial identation depth.</param>
        /// <returns>The formatted DER data.</returns>
        public static string FormatDER(byte[] asn1_der, int depth)
        {
            return FormatDER(DERParser.ParseData(asn1_der, 0), depth);
        }
        /// <summary>
        /// Format an file containing of ASN.1 DER to a string.
        /// </summary>
        /// <param name="path">The path to the file containing ASN.1 data in DER format.</param>
        /// <param name="depth">Initial identation depth.</param>
        /// <returns>The formatted DER data.</returns>
        public static string FormatDER(string path, int depth)
        {
            return FormatDER(File.ReadAllBytes(path), depth);
        }
    }
}
