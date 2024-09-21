//  Copyright 2023 Google LLC. All Rights Reserved.
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

namespace NtCoreLib.SysInfo.Features;

[StructLayout(LayoutKind.Sequential)]
struct RTL_FEATURE_CONFIGURATION
{
    public uint FeatureId;
    public uint Flags;
    public uint VariantPayload;
}

enum RTL_FEATURE_CONFIGURATION_TYPE
{
    RtlFeatureConfigurationBoot,
    RtlFeatureConfigurationRuntime,
}

internal static class NativeMethods
{
    [DllImport("ntdll.dll")]
    public static extern NtStatus RtlQueryFeatureConfiguration(
        uint FeatureId,
        RTL_FEATURE_CONFIGURATION_TYPE FeatureType,
        out ulong ChangeStamp,
        out RTL_FEATURE_CONFIGURATION FeatureConfiguration);

    [DllImport("ntdll.dll")]
    public static extern NtStatus RtlQueryAllFeatureConfigurations(
        RTL_FEATURE_CONFIGURATION_TYPE FeatureType,
        out ulong ChangeStamp,
        RTL_FEATURE_CONFIGURATION[] FeatureConfigurations,
        ref int FeatureConfigurationCount
    );
}
