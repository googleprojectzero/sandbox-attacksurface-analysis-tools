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

namespace NtApiDotNet.Win32.Debugger
{
    enum IMAGEHLP_SYMBOL_TYPE_INFO
    {
        TI_GET_SYMTAG,
        TI_GET_SYMNAME,
        TI_GET_LENGTH,
        TI_GET_TYPE,
        TI_GET_TYPEID,
        TI_GET_BASETYPE,
        TI_GET_ARRAYINDEXTYPEID,
        TI_FINDCHILDREN,
        TI_GET_DATAKIND,
        TI_GET_ADDRESSOFFSET,
        TI_GET_OFFSET,
        TI_GET_VALUE,
        TI_GET_COUNT,
        TI_GET_CHILDRENCOUNT,
        TI_GET_BITPOSITION,
        TI_GET_VIRTUALBASECLASS,
        TI_GET_VIRTUALTABLESHAPEID,
        TI_GET_VIRTUALBASEPOINTEROFFSET,
        TI_GET_CLASSPARENTID,
        TI_GET_NESTED,
        TI_GET_SYMINDEX,
        TI_GET_LEXICALPARENT,
        TI_GET_ADDRESS,
        TI_GET_THISADJUST,
        TI_GET_UDTKIND,
        TI_IS_EQUIV_TO,
        TI_GET_CALLING_CONVENTION,
        TI_IS_CLOSE_EQUIV_TO,
        TI_GTIEX_REQS_VALID,
        TI_GET_VIRTUALBASEOFFSET,
        TI_GET_VIRTUALBASEDISPINDEX,
        TI_GET_IS_REFERENCE,
        TI_GET_INDIRECTVIRTUALBASECLASS,
        TI_GET_VIRTUALBASETABLETYPE,
        IMAGEHLP_SYMBOL_TYPE_INFO_MAX
    }
}
