/**
 * Default spoofed values and constants for device bypass operations
 */

import { SpoofedDevice, SpoofedVersion, SpoofedTelephony } from '../interfaces/spoofing';
import { NetworkType, SimState } from '../enums/android';

export const DEFAULT_SPOOFED_DEVICE: SpoofedDevice = {
    BRAND: "samsung",
    MODEL: "SM-G975F",
    MANUFACTURER: "samsung",
    PRODUCT: "beyond2ltexx",
    DEVICE: "beyond2lte",
    BOARD: "exynos9820",
    HARDWARE: "exynos9820",
    FINGERPRINT: "samsung/beyond2ltexx/beyond2lte:11/RP1A.200720.012/G975FXXU8DUG1:user/release-keys",
    SERIAL: "RF8M802WZ8X",
    RADIO: "G975FXXU8DUG1",
    ANDROID_ID: "9774d56d682e549c",
    GSF_ID: "3f4c5e6d7a8b9c0d"
};

export const DEFAULT_SPOOFED_VERSION: SpoofedVersion = {
    RELEASE: "11",
    SDK_INT: 30,
    CODENAME: "REL",
    INCREMENTAL: "G975FXXU8DUG1",
    SECURITY_PATCH: "2021-07-01"
};

export const DEFAULT_SPOOFED_TELEPHONY: SpoofedTelephony = {
    mcc: "310",
    mnc: "260",
    operatorName: "T-Mobile",
    countryIso: "us",
    simState: SimState.READY,
    networkType: NetworkType.LTE,
    dataNetworkType: NetworkType.LTE
};

export const DEFAULT_SECURE_SETTINGS = {
    android_id: DEFAULT_SPOOFED_DEVICE.ANDROID_ID,
    mock_location: "0",
    auto_time: 1,
    development_settings_enabled: 0,
    adb_enabled: 0,
    airplane_mode_on: 0
} as const;

export const DEFAULT_GLOBAL_SETTINGS = {
    adb_enabled: 0,
    development_settings_enabled: 0,
    stay_on_while_plugged_in: 0,
    auto_time: 1,
    auto_time_zone: 1,
    mobile_data: 1,
    airplane_mode_on: 0
} as const;

export const ROOT_DETECTION_COMMANDS = [
    "getprop",
    "mount", 
    "build.prop",
    "id"
] as const;