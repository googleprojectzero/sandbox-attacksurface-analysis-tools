//  Copyright 2016, 2017 Google Inc. All Rights Reserved.
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

using System.Runtime.InteropServices;

namespace NtCoreLib.Image.Interop;

[StructLayout(LayoutKind.Sequential)]
internal struct IMAGE_OPTIONAL_HEADER64 : IImageOptionalHeader
{
    public IMAGE_NT_OPTIONAL_HDR_MAGIC Magic;
    public byte MajorLinkerVersion;
    public byte MinorLinkerVersion;
    public int SizeOfCode;
    public int SizeOfInitializedData;
    public int SizeOfUninitializedData;
    public int AddressOfEntryPoint;
    public int BaseOfCode;
    public long ImageBase;
    public int SectionAlignment;
    public int FileAlignment;
    public short MajorOperatingSystemVersion;
    public short MinorOperatingSystemVersion;
    public short MajorImageVersion;
    public short MinorImageVersion;
    public short MajorSubsystemVersion;
    public short MinorSubsystemVersion;
    public int Win32VersionValue;
    public int SizeOfImage;
    public int SizeOfHeaders;
    public int CheckSum;
    public short Subsystem;
    public DllCharacteristics DllCharacteristics;
    public long SizeOfStackReserve;
    public long SizeOfStackCommit;
    public long SizeOfHeapReserve;
    public long SizeOfHeapCommit;
    public int LoaderFlags;
    public int NumberOfRvaAndSizes;

    int IImageOptionalHeader.GetAddressOfEntryPoint()
    {
        return AddressOfEntryPoint;
    }

    DllCharacteristics IImageOptionalHeader.GetDllCharacteristics()
    {
        return DllCharacteristics;
    }

    long IImageOptionalHeader.GetImageBase()
    {
        return ImageBase;
    }

    IMAGE_NT_OPTIONAL_HDR_MAGIC IImageOptionalHeader.GetMagic()
    {
        return Magic;
    }

    int IImageOptionalHeader.GetSizeOfImage()
    {
        return SizeOfImage;
    }

    int IImageOptionalHeader.GetNumberOfRvaAndSizes()
    {
        return NumberOfRvaAndSizes;
    }

    int IImageOptionalHeader.GetSizeOfHeaders()
    {
        return SizeOfHeaders;
    }

    bool IImageOptionalHeader.Is64Bit => true;
}
