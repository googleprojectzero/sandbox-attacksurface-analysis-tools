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

using System;

namespace NtApiDotNet.Ndr.Marshal
{
    struct FLAGGED_WORD_BLOB : INdrConformantStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            m.WriteInt32(cBytes);
            m.WriteInt32(clSize);
            if (asData is null)
                throw new ArgumentNullException(nameof(asData));
            m.WriteConformantCharArray(asData, clSize);
        }

        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            cBytes = u.ReadInt32();
            clSize = u.ReadInt32();
            asData = u.ReadConformantCharArray();
        }

        int INdrConformantStructure.GetConformantDimensions()
        {
            return 1;
        }
        int INdrStructure.GetAlignment()
        {
            return 4;
        }
        public int cBytes;
        public int clSize;
        public char[] asData;
        
        public FLAGGED_WORD_BLOB(int cBytes, int clSize, char[] asData)
        {
            this.cBytes = cBytes;
            this.clSize = clSize;
            this.asData = asData;
        }
    }
}
