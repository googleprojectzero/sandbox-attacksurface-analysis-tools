//  Copyright 2016 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet
{
#pragma warning disable 1591

    [Flags]
    public enum ProcessMitigationUnknownPolicy
    {
        None = 0,
        Unknown1 = 0x1,
        Unknown2 = 0x2,
        Unknown4 = 0x4,
        Unknown8 = 0x8,
        Unknown10 = 0x10,
        Unknown20 = 0x20,
        Unknown40 = 0x40,
        Unknown80 = 0x80
    }

    [Flags]
    public enum ProcessMitigationImageLoadPolicy
    {
        None = 0,
        NoRemoteImages = 0x1,
        NoLowMandatoryLabelImages = 0x2,
        PreferSystem32Images = 0x4,
        AuditNoRemoteImages = 0x8,
        AuditNoLowMandatoryLabelImages = 0x10
    }

    [Flags]
    public enum ProcessMitigationBinarySignaturePolicy
    {
        None = 0,
        MicrosoftSignedOnly = 0x1,
        StoreSignedOnly = 0x2,
        MitigationOptIn = 0x4,
        AuditMicrosoftSignedOnly = 0x8,
        AuditStoreSignedOnly = 0x10,
    }

    [Flags]
    public enum ProcessMitigationSystemCallDisablePolicy
    {
        None = 0,
        DisallowWin32kSystemCalls = 0x1,
        AuditDisallowWin32kSystemCalls = 0x2
    }

    [Flags]
    public enum ProcessMitigationDynamicCodePolicy
    {
        None = 0,
        ProhibitDynamicCode = 0x1,
        AllowThreadOptOut = 0x2,
        AllowRemoteDowngrade = 0x4,
        AuditProhibitDynamicCode = 0x8
    }

    [Flags]
    public enum ProcessMitigationExtensionPointDisablePolicy
    {
        None = 0,
        DisableExtensionPoints = 0x1,
    }

    [Flags]
    public enum ProcessMitigationFontDisablePolicy
    {
        None = 0,
        DisableNonSystemFonts = 0x1,
        AuditNonSystemFontLoading = 0x2
    }

    [Flags]
    public enum ProcessMitigationControlFlowGuardPolicy
    {
        None = 0,
        EnableControlFlowGuard = 0x1,
        EnableExportSuppression = 0x2,
        StrictMode = 0x4
    }

    [Flags]
    public enum ProcessMitigationStrictHandleCheckPolicy
    {
        None = 0,
        RaiseExceptionOnInvalidHandleReference = 0x1,
        HandleExceptionsPermanentlyEnabled = 0x2
    }

    [Flags]
    public enum ProcessMitigationChildProcessPolicy
    {
        None = 0,
        NoChildProcessCreation = 0x1,
        AuditNoChildProcessCreation = 0x2,
        AllowSecureProcessCreation = 0x4
    }

    [Flags]
    public enum ProcessMitigationPayloadRestrictionPolicy
    {
        None = 0,
        EnableExportAddressFilter = 0x1,
        AuditExportAddressFilter = 0x2,
        EnableExportAddressFilterPlus = 0x4,
        AuditExportAddressFilterPlus = 0x8,
        EnableImportAddressFilter = 0x10,
        AuditImportAddressFilter = 0x20,
        EnableRopStackPivot = 0x40,
        AuditRopStackPivot = 0x80,
        EnableRopCallerCheck = 0x100,
        AuditRopCallerCheck = 0x200,
        EnableRopSimExec = 0x400,
        AuditRopSimExec = 0x800,
    }

    public enum ProcessMitigationSystemCallFilterPolicy
    {
        None = 0,
        FilterId1,
        FilterId2,
        FilterId3,
        FilterId4,
        FilterId5,
        FilterId6,
        FilterId7,
        FilterId8,
        FilterId9,
        FilterId10,
        FilterId11,
        FilterId12,
        FilterId13,
        FilterId14,
        FilterId15,
    }

    [Flags]
    public enum ProcessMitigationSideChannelIsolationPolicy
    {
        None = 0,
        SmtBranchTargetIsolation = 0x1,
        IsolateSecurityDomain = 0x2,
        DisablePageCombine = 0x4,
        SpeculativeStoreBypassDisable = 0x8
    }

    [Flags]
    public enum ProcessMitigationAslrPolicy
    {
        None = 0,
        EnableBottomUpRandomization = 0x1,
        EnableForceRelocateImages = 0x2,
        EnableHighEntropy = 0x4,
        DisallowStrippedImages = 0x8
    }

    /// <summary>
    /// Class representing various process mitigations
    /// </summary>
    public sealed class NtProcessMitigations
    {
        internal NtProcessMitigations(NtProcess process)
        {
            ProcessDepStatus dep_status = process.DepStatus;
            DisableAtlThunkEmulation = dep_status.DisableAtlThunkEmulation;
            DepEnabled = dep_status.Enabled;
            DepPermanent = dep_status.Permanent;

            int result = process.GetRawMitigationPolicy(ProcessMitigationPolicy.ASLR);
            EnableBottomUpRandomization = result.GetBit(0);
            EnableForceRelocateImages = result.GetBit(1);
            EnableHighEntropy = result.GetBit(2);
            DisallowStrippedImages = result.GetBit(3);

            DisallowWin32kSystemCalls = process.GetRawMitigationPolicy(ProcessMitigationPolicy.SystemCallDisable).GetBit(0);
            AuditDisallowWin32kSystemCalls = process.GetRawMitigationPolicy(ProcessMitigationPolicy.SystemCallDisable).GetBit(1);

            result = process.GetRawMitigationPolicy(ProcessMitigationPolicy.StrictHandleCheck);
            RaiseExceptionOnInvalidHandleReference = result.GetBit(0);
            HandleExceptionsPermanentlyEnabled = result.GetBit(1);

            result = process.GetRawMitigationPolicy(ProcessMitigationPolicy.FontDisable);
            DisableNonSystemFonts = result.GetBit(0);
            AuditNonSystemFontLoading = result.GetBit(1);

            result = process.GetRawMitigationPolicy(ProcessMitigationPolicy.DynamicCode);
            ProhibitDynamicCode = result.GetBit(0);
            AllowThreadOptOut = result.GetBit(1);
            AllowRemoteDowngrade = result.GetBit(2);
            AuditProhibitDynamicCode = result.GetBit(3);

            DisableExtensionPoints = process.GetRawMitigationPolicy(ProcessMitigationPolicy.ExtensionPointDisable).GetBit(0);

            result = process.GetRawMitigationPolicy(ProcessMitigationPolicy.ControlFlowGuard);
            EnabledControlFlowGuard = result.GetBit(0);
            EnableExportSuppression = result.GetBit(1);
            ControlFlowGuardStrictMode = result.GetBit(2);

            result = process.GetRawMitigationPolicy(ProcessMitigationPolicy.Signature);
            MicrosoftSignedOnly = result.GetBit(0);
            StoreSignedOnly = result.GetBit(1);
            SignedMitigationOptIn = result.GetBit(2);
            AuditMicrosoftSignedOnly = result.GetBit(3);
            AuditStoreSignedOnly = result.GetBit(4);

            result = process.GetRawMitigationPolicy(ProcessMitigationPolicy.ImageLoad);
            NoRemoteImages = result.GetBit(0);
            NoLowMandatoryLabelImages = result.GetBit(1);
            PreferSystem32Images = result.GetBit(2);
            AuditNoRemoteImages = result.GetBit(3);
            AuditNoLowMandatoryLabelImages = result.GetBit(4);

            SystemCallFilterId = process.GetRawMitigationPolicy(ProcessMitigationPolicy.SystemCallFilter) & 0xF;

            NoChildProcessCreation = process.IsChildProcessRestricted;
            result = process.GetRawMitigationPolicy(ProcessMitigationPolicy.ChildProcess);
            AuditNoChildProcessCreation = result.GetBit(1);
            AllowSecureProcessCreation = result.GetBit(2);

            result = process.GetRawMitigationPolicy(ProcessMitigationPolicy.PayloadRestriction);
            EnableExportAddressFilter     = result.GetBit(0);
            AuditExportAddressFilter      = result.GetBit(1);
            EnableExportAddressFilterPlus = result.GetBit(2);
            AuditExportAddressFilterPlus  = result.GetBit(3);
            EnableImportAddressFilter     = result.GetBit(4);
            AuditImportAddressFilter      = result.GetBit(5);
            EnableRopStackPivot           = result.GetBit(6);
            AuditRopStackPivot            = result.GetBit(7);
            EnableRopCallerCheck          = result.GetBit(8);
            AuditRopCallerCheck           = result.GetBit(9);
            EnableRopSimExec              = result.GetBit(10);
            AuditRopSimExec               = result.GetBit(11);

            result = process.GetRawMitigationPolicy(ProcessMitigationPolicy.SideChannelIsolation);
            SmtBranchTargetIsolation = result.GetBit(0);
            IsolateSecurityDomain = result.GetBit(1);
            DisablePageCombine = result.GetBit(2);
            SpeculativeStoreBypassDisable = result.GetBit(3);

            using (var token = NtToken.OpenProcessToken(process, TokenAccessRights.Query, false))
            {
                if (token.IsSuccess)
                {
                    IsRestricted = token.Result.Restricted;
                    IsAppContainer = token.Result.AppContainer;
                    IsLowPrivilegeAppContainer = token.Result.LowPrivilegeAppContainer;
                    IntegrityLevel = token.Result.IntegrityLevel;
                }
            }
            ProcessId = process.ProcessId;
            Name = process.Name;
            ImagePath = process.FullPath;
            Win32ImagePath = process.Win32ImagePath;
            CommandLine = process.CommandLine;
        }

        public int ProcessId { get; }
        public string Name { get; }
        public string ImagePath { get; }
        public string Win32ImagePath { get; }
        public string CommandLine { get; }
        public bool IsRestricted { get; }
        public bool IsAppContainer { get; }
        public bool IsLowPrivilegeAppContainer { get; }
        public TokenIntegrityLevel IntegrityLevel { get; }

        public bool DisallowWin32kSystemCalls { get; }
        public bool AuditDisallowWin32kSystemCalls { get; }
        public bool DepEnabled { get; }
        public bool DisableAtlThunkEmulation { get; }
        public bool DepPermanent { get; }
        public bool EnableBottomUpRandomization { get; }
        public bool EnableForceRelocateImages { get; }
        public bool EnableHighEntropy { get; }
        public bool DisallowStrippedImages { get; }
        public bool RaiseExceptionOnInvalidHandleReference { get; }
        public bool HandleExceptionsPermanentlyEnabled { get; }
        public bool DisableNonSystemFonts { get; }
        public bool AuditNonSystemFontLoading { get; }
        public bool ProhibitDynamicCode { get; }
        public bool DisableExtensionPoints { get; }
        public bool EnabledControlFlowGuard { get; }
        public bool EnableExportSuppression { get; }
        public bool ControlFlowGuardStrictMode { get; }
        public bool MicrosoftSignedOnly { get; }
        public bool StoreSignedOnly { get; }
        public bool SignedMitigationOptIn { get; }
        public bool AuditMicrosoftSignedOnly { get; }
        public bool AuditStoreSignedOnly { get; }
        public bool NoRemoteImages { get; }
        public bool NoLowMandatoryLabelImages { get; }
        public bool PreferSystem32Images { get; }
        public bool AuditNoRemoteImages { get; }
        public bool AuditNoLowMandatoryLabelImages { get; }
        public int SystemCallFilterId { get; }
        public bool AllowThreadOptOut { get; }
        public bool AllowRemoteDowngrade { get; }
        public bool AuditProhibitDynamicCode { get; }
        public bool NoChildProcessCreation { get; }

        public bool AuditNoChildProcessCreation { get; }
        public bool AllowSecureProcessCreation { get; }
        public bool EnableExportAddressFilter { get; }
        public bool AuditExportAddressFilter { get; }
        public bool EnableExportAddressFilterPlus { get; }
        public bool AuditExportAddressFilterPlus { get; }
        public bool EnableImportAddressFilter { get; }
        public bool AuditImportAddressFilter { get; }
        public bool EnableRopStackPivot { get; }
        public bool AuditRopStackPivot { get; }
        public bool EnableRopCallerCheck { get; }
        public bool AuditRopCallerCheck { get; }
        public bool EnableRopSimExec { get; }
        public bool AuditRopSimExec { get; }
        public bool SmtBranchTargetIsolation { get; }
        public bool IsolateSecurityDomain { get; }
        public bool DisablePageCombine { get; }
        public bool SpeculativeStoreBypassDisable { get; }
    }
#pragma warning restore 1591
}
