using NtApiDotNet;

namespace NtApiDotNet
{
    public class NtProcessMitigations
    {
        internal NtProcessMitigations(NtProcess process)
        {
            NtApiDotNet.ProcessDepStatus dep_status = process.GetProcessDepStatus();
            DisableAtlThunkEmulation = dep_status.DisableAtlThunkEmulation;
            DepEnabled = dep_status.Enabled;
            DepPermanent = dep_status.Permanent;
                    
            int result = process.GetProcessMitigationPolicy(ProcessMitigationPolicy.ProcessASLRPolicy);
            EnableForceRelocateImages = result.GetBit(0);
            EnableBottomUpRandomization = result.GetBit(1);
            EnableHighEntropy = result.GetBit(2);
            DisallowStrippedImages = result.GetBit(3);

            DisallowWin32kSystemCalls = process.GetProcessMitigationPolicy(ProcessMitigationPolicy.ProcessSystemCallDisablePolicy).GetBit(0);
            result = process.GetProcessMitigationPolicy(ProcessMitigationPolicy.ProcessStrictHandleCheckPolicy);
            RaiseExceptionOnInvalidHandleReference = result.GetBit(0);
            HandleExceptionsPermanentlyEnabled = result.GetBit(1);

            result = process.GetProcessMitigationPolicy(ProcessMitigationPolicy.ProcessFontDisablePolicy);
            DisableNonSystemFonts = result.GetBit(0);
            AuditNonSystemFontLoading = result.GetBit(1);

            result = process.GetProcessMitigationPolicy(ProcessMitigationPolicy.ProcessDynamicCodePolicy);
            ProhibitDynamicCode = result.GetBit(0);
            AllowThreadOptOut = result.GetBit(1);
            DisableExtensionPoints = process.GetProcessMitigationPolicy(ProcessMitigationPolicy.ProcessExtensionPointDisablePolicy).GetBit(0);
            result = process.GetProcessMitigationPolicy(ProcessMitigationPolicy.ProcessSignaturePolicy);
            MicrosoftSignedOnly = result.GetBit(0);
            StoreSignedOnly = result.GetBit(1);
            SignedMitigationOptIn = result.GetBit(2);

            result = process.GetProcessMitigationPolicy(ProcessMitigationPolicy.ProcessImageLoadPolicy);
            NoRemoteImages = result.GetBit(0);
            NoLowMandatoryLabelImages = result.GetBit(1);
            PreferSystem32Images = result.GetBit(2);
        }

        public bool DisallowWin32kSystemCalls { get; private set; }
        public bool DepEnabled { get; private set; }
        public bool DisableAtlThunkEmulation { get; private set; }
        public bool DepPermanent { get; private set; }
        public bool EnableBottomUpRandomization { get; private set; }
        public bool EnableForceRelocateImages { get; private set; }
        public bool EnableHighEntropy { get; private set; }
        public bool DisallowStrippedImages { get; private set; }
        public bool RaiseExceptionOnInvalidHandleReference { get; private set; }
        public bool HandleExceptionsPermanentlyEnabled { get; private set; }
        public bool DisableNonSystemFonts { get; private set; }
        public bool AuditNonSystemFontLoading { get; private set; }
        public bool ProhibitDynamicCode { get; private set; }
        public bool DisableExtensionPoints { get; private set; }
        public bool MicrosoftSignedOnly { get; private set; }
        public bool StoreSignedOnly { get; private set; }
        public bool SignedMitigationOptIn { get; private set; }
        public bool NoRemoteImages { get; private set; }
        public bool NoLowMandatoryLabelImages { get; private set; }
        public bool PreferSystem32Images { get; private set; }
        public bool AllowThreadOptOut { get; private set; }
    }
}
