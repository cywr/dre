/**
 * Interfaces for device spoofing and bypass operations
 */

export interface HookNamespace {
    readonly NAME: string;
    performNow(...args: any[]): void;
}

export interface AntiEmulationConfig {
    sensors?: SensorInfo[];
    device?: SpoofedDevice;
    telephony?: SpoofedTelephony;
    version?: SpoofedVersion;
}

// Device spoofing interfaces
export interface SpoofedDevice {
    BRAND: string;
    MODEL: string;
    MANUFACTURER: string;
    PRODUCT: string;
    DEVICE: string;
    BOARD: string;
    HARDWARE: string;
    FINGERPRINT: string;
    SERIAL: string;
    RADIO: string;
    ANDROID_ID: string;
    GSF_ID: string;
}

export interface SpoofedVersion {
    RELEASE: string;
    SDK_INT: number;
    CODENAME: string;
    INCREMENTAL: string;
    SECURITY_PATCH: string;
}

export interface SpoofedTelephony {
    mcc: string;
    mnc: string;
    operatorName: string;
    countryIso: string;
    simState: number;
    networkType: number;
    dataNetworkType: number;
}

export interface SensorInfo {
    name: string;
    vendor: string;
    version: number;
    type: number;
    maximumRange: number;
    resolution: number;
    power: number;
    minDelay: number;
    fifoReservedEventCount: number;
    fifoMaxEventCount: number;
    stringType: string;
    maxDelay: number;
    id: number;
}

// Settings interfaces
export interface SettingsValues {
    [key: string]: string | number;
}

export interface SecuritySettings {
    developmentSettingsEnabled: number;
    adbEnabled: number;
    mockLocation: string;
    airplaneModeOn: number;
    autoTime: number;
}