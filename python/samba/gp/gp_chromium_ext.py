# gp_chromium_ext samba gpo policy
# Copyright (C) David Mulder <dmulder@suse.com> 2021
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import json
from samba.gp.gpclass import gp_pol_ext, gp_file_applier
from samba.dcerpc import misc
from samba.common import get_string
from samba.gp.util.logging import log
from tempfile import NamedTemporaryFile

def parse_entry_data(name, e):
    dict_entries = ['VirtualKeyboardFeatures',
                    'DeviceArcDataSnapshotHours',
                    'RequiredClientCertificateForDevice',
                    'RequiredClientCertificateForUser',
                    'RegisteredProtocolHandlers',
                    'WebUsbAllowDevicesForUrls',
                    'DeviceAutoUpdateTimeRestrictions',
                    'DeviceUpdateStagingSchedule',
                    'DeviceMinimumVersion',
                    'DeviceDisplayResolution',
                    'ExtensionSettings',
                    'KerberosAccounts',
                    'NetworkFileSharesPreconfiguredShares',
                    'NetworkThrottlingEnabled',
                    'TPMFirmwareUpdateSettings',
                    'DeviceOffHours',
                    'ParentAccessCodeConfig',
                    'PerAppTimeLimits',
                    'PerAppTimeLimitsWhitelist',
                    'PerAppTimeLimitsAllowlist',
                    'UsageTimeLimit',
                    'PluginVmImage',
                    'DeviceLoginScreenPowerManagement',
                    'PowerManagementIdleSettings',
                    'ScreenLockDelays',
                    'ScreenBrightnessPercent',
                    'DevicePowerPeakShiftDayConfig',
                    'DeviceAdvancedBatteryChargeModeDayConfig',
                    'PrintingPaperSizeDefault',
                    'AutoLaunchProtocolsFromOrigins',
                    'BrowsingDataLifetime',
                    'DataLeakPreventionRulesList',
                    'DeviceLoginScreenWebUsbAllowDevicesForUrls',
                    'DeviceScheduledUpdateCheck',
                    'KeyPermissions',
                    'ManagedBookmarks',
                    'ManagedConfigurationPerOrigin',
                    'ProxySettings',
                    'SystemProxySettings',
                    'WebAppInstallForceList']
    bools = ['ShowAccessibilityOptionsInSystemTrayMenu',
             'LargeCursorEnabled',
             'SpokenFeedbackEnabled',
             'HighContrastEnabled',
             'VirtualKeyboardEnabled',
             'StickyKeysEnabled',
             'KeyboardDefaultToFunctionKeys',
             'DictationEnabled',
             'SelectToSpeakEnabled',
             'KeyboardFocusHighlightEnabled',
             'CursorHighlightEnabled',
             'CaretHighlightEnabled',
             'MonoAudioEnabled',
             'AccessibilityShortcutsEnabled',
             'AutoclickEnabled',
             'DeviceLoginScreenDefaultLargeCursorEnabled',
             'DeviceLoginScreenDefaultSpokenFeedbackEnabled',
             'DeviceLoginScreenDefaultHighContrastEnabled',
             'DeviceLoginScreenDefaultVirtualKeyboardEnabled',
             'DeviceLoginScreenLargeCursorEnabled',
             'DeviceLoginScreenSpokenFeedbackEnabled',
             'DeviceLoginScreenHighContrastEnabled',
             'DeviceLoginScreenVirtualKeyboardEnabled',
             'DeviceLoginScreenDictationEnabled',
             'DeviceLoginScreenSelectToSpeakEnabled',
             'DeviceLoginScreenCursorHighlightEnabled',
             'DeviceLoginScreenCaretHighlightEnabled',
             'DeviceLoginScreenMonoAudioEnabled',
             'DeviceLoginScreenAutoclickEnabled',
             'DeviceLoginScreenStickyKeysEnabled',
             'DeviceLoginScreenKeyboardFocusHighlightEnabled',
             'DeviceLoginScreenShowOptionsInSystemTrayMenu',
             'DeviceLoginScreenAccessibilityShortcutsEnabled',
             'FloatingAccessibilityMenuEnabled',
             'ArcEnabled',
             'UnaffiliatedArcAllowed',
             'AppRecommendationZeroStateEnabled',
             'DeviceBorealisAllowed',
             'UserBorealisAllowed',
             'SystemUse24HourClock',
             'DefaultSearchProviderEnabled',
             'ChromeOsReleaseChannelDelegated',
             'DeviceAutoUpdateDisabled',
             'DeviceAutoUpdateP2PEnabled',
             'DeviceUpdateHttpDownloadsEnabled',
             'RebootAfterUpdate',
             'BlockExternalExtensions',
             'VoiceInteractionContextEnabled',
             'VoiceInteractionHotwordEnabled',
             'EnableMediaRouter',
             'ShowCastIconInToolbar',
             'DriveDisabled',
             'DriveDisabledOverCellular',
             'DisableAuthNegotiateCnameLookup',
             'EnableAuthNegotiatePort',
             'BasicAuthOverHttpEnabled',
             'AuthNegotiateDelegateByKdcPolicy',
             'AllowCrossOriginAuthPrompt',
             'NtlmV2Enabled',
             'IntegratedWebAuthenticationAllowed',
             'BrowserSwitcherEnabled',
             'BrowserSwitcherKeepLastChromeTab',
             'BrowserSwitcherUseIeSitelist',
             'VirtualMachinesAllowed',
             'CrostiniAllowed',
             'DeviceUnaffiliatedCrostiniAllowed',
             'CrostiniExportImportUIAllowed',
             'CrostiniPortForwardingAllowed',
             'NativeMessagingUserLevelHosts',
             'NetworkFileSharesAllowed',
             'NetBiosShareDiscoveryEnabled',
             'NTLMShareAuthenticationEnabled',
             'DeviceDataRoamingEnabled',
             'DeviceWiFiFastTransitionEnabled',
             'DeviceWiFiAllowed',
             'DeviceAllowBluetooth',
             'DeviceAllowRedeemChromeOsRegistrationOffers',
             'DeviceQuirksDownloadEnabled',
             'SuggestedContentEnabled',
             'DeviceShowLowDiskSpaceNotification',
             'PasswordManagerEnabled',
             'PasswordLeakDetectionEnabled',
             'PluginVmAllowed',
             'PluginVmDataCollectionAllowed',
             'UserPluginVmAllowed',
             'DeviceRebootOnShutdown',
             'PowerManagementUsesAudioActivity',
             'PowerManagementUsesVideoActivity',
             'AllowWakeLocks',
             'AllowScreenWakeLocks',
             'WaitForInitialUserActivity',
             'PowerSmartDimEnabled',
             'DevicePowerPeakShiftEnabled',
             'DeviceBootOnAcEnabled',
             'DeviceAdvancedBatteryChargeModeEnabled',
             'DeviceUsbPowerShareEnabled',
             'PrintingEnabled',
             'CloudPrintProxyEnabled',
             'PrintingSendUsernameAndFilenameEnabled',
             'CloudPrintSubmitEnabled',
             'DisablePrintPreview',
             'PrintHeaderFooter',
             'PrintPreviewUseSystemDefaultPrinter',
             'UserNativePrintersAllowed',
             'UserPrintersAllowed',
             'DeletePrintJobHistoryAllowed',
             'DeviceLoginScreenPrivacyScreenEnabled',
             'PrivacyScreenEnabled',
             'PinUnlockWeakPinsAllowed',
             'PinUnlockAutosubmitEnabled',
             'RemoteAccessHostFirewallTraversal',
             'RemoteAccessHostRequireCurtain',
             'RemoteAccessHostAllowClientPairing',
             'RemoteAccessHostAllowRelayedConnection',
             'RemoteAccessHostAllowUiAccessForRemoteAssistance',
             'RemoteAccessHostAllowFileTransfer',
             'RemoteAccessHostAllowRemoteAccessConnections',
             'AttestationEnabledForUser',
             'SafeBrowsingEnabled',
             'SafeBrowsingExtendedReportingEnabled',
             'DeviceGuestModeEnabled',
             'DeviceAllowNewUsers',
             'DeviceShowUserNamesOnSignin',
             'DeviceEphemeralUsersEnabled',
             'DeviceShowNumericKeyboardForPassword',
             'DeviceFamilyLinkAccountsAllowed',
             'ShowHomeButton',
             'HomepageIsNewTabPage',
             'DeviceMetricsReportingEnabled',
             'DeviceWilcoDtcAllowed',
             'AbusiveExperienceInterventionEnforce',
             'AccessibilityImageLabelsEnabled',
             'AdditionalDnsQueryTypesEnabled',
             'AdvancedProtectionAllowed',
             'AllowDeletingBrowserHistory',
             'AllowDinosaurEasterEgg',
             'AllowFileSelectionDialogs',
             'AllowScreenLock',
             'AllowSyncXHRInPageDismissal',
             'AlternateErrorPagesEnabled',
             'AlwaysOpenPdfExternally',
             'AppCacheForceEnabled',
             'AudioCaptureAllowed',
             'AudioOutputAllowed',
             'AudioProcessHighPriorityEnabled',
             'AudioSandboxEnabled',
             'AutoFillEnabled',
             'AutofillAddressEnabled',
             'AutofillCreditCardEnabled',
             'AutoplayAllowed',
             'BackgroundModeEnabled',
             'BlockThirdPartyCookies',
             'BookmarkBarEnabled',
             'BrowserAddPersonEnabled',
             'BrowserGuestModeEnabled',
             'BrowserGuestModeEnforced',
             'BrowserLabsEnabled',
             'BrowserNetworkTimeQueriesEnabled',
             'BuiltInDnsClientEnabled',
             'CECPQ2Enabled',
             'CaptivePortalAuthenticationIgnoresProxy',
             'ChromeCleanupEnabled',
             'ChromeCleanupReportingEnabled',
             'ChromeOsLockOnIdleSuspend',
             'ClickToCallEnabled',
             'CloudManagementEnrollmentMandatory',
             'CloudPolicyOverridesPlatformPolicy',
             'CloudUserPolicyMerge',
             'CommandLineFlagSecurityWarningsEnabled',
             'ComponentUpdatesEnabled',
             'DNSInterceptionChecksEnabled',
             'DataLeakPreventionReportingEnabled',
             'DefaultBrowserSettingEnabled',
             'DefaultSearchProviderContextMenuAccessAllowed',
             'DeveloperToolsDisabled',
             'DeviceAllowMGSToStoreDisplayProperties',
             'DeviceDebugPacketCaptureAllowed',
             'DeviceLocalAccountManagedSessionEnabled',
             'DeviceLoginScreenPrimaryMouseButtonSwitch',
             'DevicePciPeripheralDataAccessEnabled',
             'DevicePowerwashAllowed',
             'DeviceSystemWideTracingEnabled',
             'Disable3DAPIs',
             'DisableSafeBrowsingProceedAnyway',
             'DisableScreenshots',
             'EasyUnlockAllowed',
             'EditBookmarksEnabled',
             'EmojiSuggestionEnabled',
             'EnableDeprecatedPrivetPrinting',
             'EnableOnlineRevocationChecks',
             'EnableSyncConsent',
             'EnterpriseHardwarePlatformAPIEnabled',
             'ExternalProtocolDialogShowAlwaysOpenCheckbox',
             'ExternalStorageDisabled',
             'ExternalStorageReadOnly',
             'ForceBrowserSignin',
             'ForceEphemeralProfiles',
             'ForceGoogleSafeSearch',
             'ForceMaximizeOnFirstRun',
             'ForceSafeSearch',
             'ForceYouTubeSafetyMode',
             'FullscreenAlertEnabled',
             'FullscreenAllowed',
             'GloballyScopeHTTPAuthCacheEnabled',
             'HardwareAccelerationModeEnabled',
             'HideWebStoreIcon',
             'ImportAutofillFormData',
             'ImportBookmarks',
             'ImportHistory',
             'ImportHomepage',
             'ImportSavedPasswords',
             'ImportSearchEngine',
             'IncognitoEnabled',
             'InsecureFormsWarningsEnabled',
             'InsecurePrivateNetworkRequestsAllowed',
             'InstantTetheringAllowed',
             'IntensiveWakeUpThrottlingEnabled',
             'JavascriptEnabled',
             'LacrosAllowed',
             'LacrosSecondaryProfilesAllowed',
             'LockScreenMediaPlaybackEnabled',
             'LoginDisplayPasswordButtonEnabled',
             'ManagedGuestSessionPrivacyWarningsEnabled',
             'MediaRecommendationsEnabled',
             'MediaRouterCastAllowAllIPs',
             'MetricsReportingEnabled',
             'NTPCardsVisible',
             'NTPCustomBackgroundEnabled',
             'NativeWindowOcclusionEnabled',
             'NearbyShareAllowed',
             'PaymentMethodQueryEnabled',
             'PdfAnnotationsEnabled',
             'PhoneHubAllowed',
             'PhoneHubNotificationsAllowed',
             'PhoneHubTaskContinuationAllowed',
             'PolicyAtomicGroupsEnabled',
             'PrimaryMouseButtonSwitch',
             'PromotionalTabsEnabled',
             'PromptForDownloadLocation',
             'QuicAllowed',
             'RendererCodeIntegrityEnabled',
             'RequireOnlineRevocationChecksForLocalAnchors',
             'RoamingProfileSupportEnabled',
             'SSLErrorOverrideAllowed',
             'SafeBrowsingForTrustedSourcesEnabled',
             'SavingBrowserHistoryDisabled',
             'ScreenCaptureAllowed',
             'ScrollToTextFragmentEnabled',
             'SearchSuggestEnabled',
             'SecondaryGoogleAccountSigninAllowed',
             'SharedArrayBufferUnrestrictedAccessAllowed',
             'SharedClipboardEnabled',
             'ShowAppsShortcutInBookmarkBar',
             'ShowFullUrlsInAddressBar',
             'ShowLogoutButtonInTray',
             'SignedHTTPExchangeEnabled',
             'SigninAllowed',
             'SigninInterceptionEnabled',
             'SitePerProcess',
             'SmartLockSigninAllowed',
             'SmsMessagesAllowed',
             'SpellCheckServiceEnabled',
             'SpellcheckEnabled',
             'StartupBrowserWindowLaunchSuppressed',
             'StricterMixedContentTreatmentEnabled',
             'SuggestLogoutAfterClosingLastWindow',
             'SuppressDifferentOriginSubframeDialogs',
             'SuppressUnsupportedOSWarning',
             'SyncDisabled',
             'TargetBlankImpliesNoOpener',
             'TaskManagerEndProcessEnabled',
             'ThirdPartyBlockingEnabled',
             'TouchVirtualKeyboardEnabled',
             'TranslateEnabled',
             'TripleDESEnabled',
             'UnifiedDesktopEnabledByDefault',
             'UrlKeyedAnonymizedDataCollectionEnabled',
             'UserAgentClientHintsEnabled',
             'UserFeedbackAllowed',
             'VideoCaptureAllowed',
             'VmManagementCliAllowed',
             'VpnConfigAllowed',
             'WPADQuickCheckEnabled',
             'WebRtcAllowLegacyTLSProtocols',
             'WebRtcEventLogCollectionAllowed',
             'WifiSyncAndroidAllowed',
             'WindowOcclusionEnabled']
    if name in dict_entries:
        return json.loads(get_string(e.data))
    elif e.type == misc.REG_DWORD and name in bools:
        return e.data == 1
    return e.data

def assign_entry(policies, e):
    if e.valuename.isnumeric():
        name = e.keyname.split('\\')[-1]
        if name not in policies:
            policies[name] = []
        policies[name].append(parse_entry_data(name, e))
    else:
        name = e.valuename
        policies[name] = parse_entry_data(name, e)

def convert_pol_to_json(section, entries):
    managed = {}
    recommended = {}
    recommended_section = '\\'.join([section, 'Recommended'])
    for e in entries:
        if '**delvals.' in e.valuename:
            continue
        if e.keyname.startswith(recommended_section):
            assign_entry(recommended, e)
        elif e.keyname.startswith(section):
            assign_entry(managed, e)
    return managed, recommended

class gp_chromium_ext(gp_pol_ext, gp_file_applier):
    managed_policies_path = '/etc/chromium/policies/managed'
    recommended_policies_path = '/etc/chromium/policies/recommended'

    def __str__(self):
        return 'Google/Chromium'

    def process_group_policy(self, deleted_gpo_list, changed_gpo_list,
                             policy_dir=None):
        if policy_dir is not None:
            self.recommended_policies_path = os.path.join(policy_dir,
                                                            'recommended')
            self.managed_policies_path = os.path.join(policy_dir, 'managed')
        # Create the policy directories if necessary
        if not os.path.exists(self.recommended_policies_path):
            os.makedirs(self.recommended_policies_path, mode=0o755,
                        exist_ok=True)
        if not os.path.exists(self.managed_policies_path):
            os.makedirs(self.managed_policies_path, mode=0o755,
                        exist_ok=True)
        for guid, settings in deleted_gpo_list:
            if str(self) in settings:
                for attribute, policies in settings[str(self)].items():
                    try:
                        json.loads(policies)
                    except json.decoder.JSONDecodeError:
                        self.unapply(guid, attribute, policies)
                    else:
                        # Policies were previously stored all in one file, but
                        # the Chromium documentation says this is not
                        # necessary. Unapply the old policy file if json was
                        # stored in the cache (now we store a hash and file
                        # names instead).
                        if attribute == 'recommended':
                            fname = os.path.join(self.recommended_policies_path,
                                                 'policies.json')
                        elif attribute == 'managed':
                            fname = os.path.join(self.managed_policies_path,
                                                 'policies.json')
                        self.unapply(guid, attribute, fname)

        for gpo in changed_gpo_list:
            if gpo.file_sys_path:
                section = 'Software\\Policies\\Google\\Chrome'
                pol_file = 'MACHINE/Registry.pol'
                path = os.path.join(gpo.file_sys_path, pol_file)
                pol_conf = self.parse(path)
                if not pol_conf:
                    continue

                managed, recommended = convert_pol_to_json(section,
                                                           pol_conf.entries)
                def applier_func(policies, location):
                    try:
                        with NamedTemporaryFile(mode='w+', prefix='gp_',
                                                delete=False,
                                                dir=location,
                                                suffix='.json') as f:
                            json.dump(policies, f)
                            os.chmod(f.name, 0o644)
                            log.debug('Wrote Chromium preferences', policies)
                            return [f.name]
                    except PermissionError:
                        log.debug('Failed to write Chromium preferences',
                                  policies)
                value_hash = self.generate_value_hash(json.dumps(managed))
                self.apply(gpo.name, 'managed', value_hash, applier_func,
                           managed, self.managed_policies_path)
                value_hash = self.generate_value_hash(json.dumps(recommended))
                self.apply(gpo.name, 'recommended', value_hash, applier_func,
                           recommended, self.recommended_policies_path)

    def rsop(self, gpo):
        output = {}
        pol_file = 'MACHINE/Registry.pol'
        section = 'Software\\Policies\\Google\\Chrome'
        if gpo.file_sys_path:
            path = os.path.join(gpo.file_sys_path, pol_file)
            pol_conf = self.parse(path)
            if not pol_conf:
                return output
            for e in pol_conf.entries:
                if e.keyname.startswith(section):
                    output['%s\\%s' % (e.keyname, e.valuename)] = e.data
        return output

class gp_chrome_ext(gp_chromium_ext):
    managed_policies_path = '/etc/opt/chrome/policies/managed'
    recommended_policies_path = '/etc/opt/chrome/policies/recommended'

    def __str__(self):
        return 'Google/Chrome'
