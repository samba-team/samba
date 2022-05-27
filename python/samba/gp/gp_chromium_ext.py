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
from samba.gp.gpclass import gp_pol_ext
from samba.dcerpc import misc
from samba.common import get_string
from samba.gp.util.logging import log

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

def convert_pol_to_json(managed, recommended, section, entries):
    recommended_section = '\\'.join([section, 'Recommended'])
    for e in entries:
        if '**delvals.' in e.valuename:
            continue
        if e.keyname.startswith(recommended_section):
            assign_entry(recommended, e)
        elif e.keyname.startswith(section):
            assign_entry(managed, e)
    return managed, recommended

class gp_chromium_ext(gp_pol_ext):
    __managed_policies_path = '/etc/chromium/policies/managed'
    __recommended_policies_path = '/etc/chromium/policies/recommended'

    def __str__(self):
        return 'Google/Chromium'

    def set_managed_machine_policy(self, managed):
        try:
            managed_policies = os.path.join(self.__managed_policies_path,
                                            'policies.json')
            os.makedirs(self.__managed_policies_path, exist_ok=True)
            with open(managed_policies, 'w') as f:
                json.dump(managed, f)
                log.debug('Wrote Chromium preferences', managed_policies)
        except PermissionError:
            log.debug('Failed to write Chromium preferences',
                      managed_policies)


    def set_recommended_machine_policy(self, recommended):
        try:
            recommended_policies = os.path.join(self.__recommended_policies_path,
                                                'policies.json')
            os.makedirs(self.__recommended_policies_path, exist_ok=True)
            with open(recommended_policies, 'w') as f:
                json.dump(recommended, f)
                log.debug('Wrote Chromium preferences', recommended_policies)
        except PermissionError:
            log.debug('Failed to write Chromium preferences',
                      recommended_policies)

    def get_managed_machine_policy(self):
        managed_policies = os.path.join(self.__managed_policies_path,
                                        'policies.json')
        if os.path.exists(managed_policies):
            with open(managed_policies, 'r') as r:
                managed = json.load(r)
                log.debug('Read Chromium preferences', managed_policies)
        else:
            managed = {}
        return managed

    def get_recommended_machine_policy(self):
        recommended_policies = os.path.join(self.__recommended_policies_path,
                                            'policies.json')
        if os.path.exists(recommended_policies):
            with open(recommended_policies, 'r') as r:
                recommended = json.load(r)
                log.debug('Read Chromium preferences', recommended_policies)
        else:
            recommended = {}
        return recommended

    def process_group_policy(self, deleted_gpo_list, changed_gpo_list,
                             policy_dir=None):
        if policy_dir is not None:
            self.__recommended_policies_path = os.path.join(policy_dir,
                                                            'recommended')
            self.__managed_policies_path = os.path.join(policy_dir, 'managed')
        for guid, settings in deleted_gpo_list:
            self.gp_db.set_guid(guid)
            if str(self) in settings:
                for attribute, policies in settings[str(self)].items():
                    if attribute == 'managed':
                        self.set_managed_machine_policy(json.loads(policies))
                    elif attribute == 'recommended':
                        self.set_recommended_machine_policy(json.loads(policies))
                    self.gp_db.delete(str(self), attribute)
            self.gp_db.commit()

        for gpo in changed_gpo_list:
            if gpo.file_sys_path:
                section = 'Software\\Policies\\Google\\Chrome'
                self.gp_db.set_guid(gpo.name)
                pol_file = 'MACHINE/Registry.pol'
                path = os.path.join(gpo.file_sys_path, pol_file)
                pol_conf = self.parse(path)
                if not pol_conf:
                    continue

                managed = self.get_managed_machine_policy()
                recommended = self.get_recommended_machine_policy()
                self.gp_db.store(str(self), 'managed', json.dumps(managed))
                self.gp_db.store(str(self), 'recommended',
                                 json.dumps(recommended))
                managed, recommended = convert_pol_to_json(managed,
                                               recommended, section,
                                               pol_conf.entries)
                self.set_managed_machine_policy(managed)
                self.set_recommended_machine_policy(recommended)
                self.gp_db.commit()

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
    __managed_policies_path = '/etc/opt/chrome/policies/managed'
    __recommended_policies_path = '/etc/opt/chrome/policies/recommended'

    def __str__(self):
        return 'Google/Chrome'
