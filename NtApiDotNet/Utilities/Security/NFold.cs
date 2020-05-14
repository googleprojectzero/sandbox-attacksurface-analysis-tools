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

// Original license from KRB5 source code on which this code is derived.
/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

using System.Text;

namespace NtApiDotNet.Utilities.Security
{
    /// <summary>
    /// Class to perform the n-fold operation for Kerberos key derivation.
    /// </summary>
    public static class NFold
    {
        /// <summary>
        /// Perform an n-fold operation.
        /// </summary>
        /// <param name="in_data">The input data as a string.</param>
        /// <param name="out_length">The output length in bytes.</param>
        /// <returns>The computed n-folded byte array.</returns>
        public static byte[] Compute(string in_data, int out_length)
        {
            return Compute(Encoding.ASCII.GetBytes(in_data), out_length);
        }

        /// <summary>
        /// Perform an n-fold operation.
        /// </summary>
        /// <param name="in_data">The input data.</param>
        /// <param name="out_length">The output length in bytes.</param>
        /// <returns>The computed n-folded byte array.</returns>
        public static byte[] Compute(byte[] in_data, int out_length)
        {
            int a, b, c, lcm;
            int byte_val, i, msbit;

            int in_length = in_data.Length;

            /* first compute lcm(n,k) */

            a = out_length;
            b = in_length;

            while (b != 0)
            {
                c = b;
                b = a % b;
                a = c;
            }

            lcm = out_length * in_length / a;

            /* now do the real work */

            byte[] out_data = new byte[out_length];

            byte_val = 0;

            /* this will end up cycling through k lcm(k,n)/k times, which
               is correct */
            for (i = lcm - 1; i >= 0; i--)
            {
                /* compute the msbit in k which gets added into this byte */
                msbit = (/* first, start with the msbit in the first, unrotated
                    byte */
                    ((in_length << 3) - 1)
                    /* then, for each byte, shift to the right for each
                       repetition */
                    + (((in_length << 3) + 13) * (i / in_length))
                    /* last, pick out the correct byte within that
                       shifted repetition */
                    + ((in_length - (i % in_length)) << 3)
                ) % (in_length << 3);

                /* pull out the byte value itself */
                byte_val += (((in_data[((in_length - 1) - (msbit >> 3)) % in_length] << 8) |
                          (in_data[((in_length) - (msbit >> 3)) % in_length]))
                         >> ((msbit & 7) + 1)) & 0xff;

                /* do the addition */
                byte_val += out_data[i % out_length];
                out_data[i % out_length] = (byte)(byte_val & 0xff);

                /* keep around the carry bit, if any */
                byte_val >>= 8;

            }

            /* if there's a carry bit left over, add it back in */
            if (byte_val != 0)
            {
                for (i = out_length - 1; i >= 0; i--)
                {
                    /* do the addition */
                    byte_val += out_data[i];
                    out_data[i] = (byte)(byte_val & 0xff);

                    /* keep around the carry bit, if any */
                    byte_val >>= 8;
                }
            }

            return out_data;
        }
    }
}
