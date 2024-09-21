//  Copyright 2022 Google LLC. All Rights Reserved.
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

namespace NtApiDotNet.Utilities.ASN1.Parser
{
    /// <summary>
    /// Class to represent a ASN1 universal object.
    /// </summary>
    public class ASN1Universal : ASN1Object
    {
        /// <summary>
        /// The universal type tag.
        /// </summary>
        new public ASN1UniversalTag Tag => (ASN1UniversalTag)base.Tag;

        private protected override string FormatTag()
        {
            return Tag.ToString();
        }

        new internal static ASN1Object ToObject(DERValue value)
        {
            if (value.Constructed)
            {
                return new ASN1Universal(value);
            }
            return new ASN1UniversalPrimitive(value);
        }

        internal ASN1Universal(DERValue value) : base(value)
        {
            System.Diagnostics.Debug.Assert(value.Type == DERTagType.Universal);
        }
    }
}
