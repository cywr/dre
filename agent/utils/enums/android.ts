/**
 * Android-specific enums and constants for bypass operations
 */

export enum NetworkType {
    UNKNOWN = 0,
    GPRS = 1,
    EDGE = 2,
    UMTS = 3,
    CDMA = 4,
    EVDO_0 = 5,
    EVDO_A = 6,
    RTT_1XRTT = 7,
    HSDPA = 8,
    HSUPA = 9,
    HSPA = 10,
    IDEN = 11,
    EVDO_B = 12,
    LTE = 13,
    EHRPD = 14,
    HSPAP = 15,
    GSM = 16,
    TD_SCDMA = 17,
    IWLAN = 18,
    NR = 20
}

export enum SensorType {
    ACCELEROMETER = 1,
    MAGNETIC_FIELD = 2,
    ORIENTATION = 3,
    GYROSCOPE = 4,
    LIGHT = 5,
    PRESSURE = 6,
    TEMPERATURE = 7,
    PROXIMITY = 8,
    GRAVITY = 9,
    LINEAR_ACCELERATION = 10,
    ROTATION_VECTOR = 11,
    RELATIVE_HUMIDITY = 12,
    AMBIENT_TEMPERATURE = 13,
    MAGNETIC_FIELD_UNCALIBRATED = 14,
    GAME_ROTATION_VECTOR = 15,
    GYROSCOPE_UNCALIBRATED = 16,
    SIGNIFICANT_MOTION = 17,
    STEP_DETECTOR = 18,
    STEP_COUNTER = 19,
    GEOMAGNETIC_ROTATION_VECTOR = 20
}

export enum SimState {
    UNKNOWN = 0,
    ABSENT = 1,
    PIN_REQUIRED = 2,
    PUK_REQUIRED = 3,
    NETWORK_LOCKED = 4,
    READY = 5,
    NOT_READY = 6,
    PERM_DISABLED = 7,
    CARD_IO_ERROR = 8,
    CARD_RESTRICTED = 9
}

export const DRM_UUIDS = {
    WIDEVINE: "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed",
    CLEARKEY: "1077efec-c0b2-4d02-ace3-3c1e52e2fb4b",
    PLAYREADY: "9a04f079-9840-4286-ab92-e65be0885f95",
    FAIRPLAY: "29701fe4-3cc7-4a34-8c5b-ae90c7439a47"
} as const;

export const SENSOR_VENDOR_REPLACEMENTS = {
    "The Android Open Source Project": "AMS",
    "AOSP": "AMS",
    "Goldfish ": ""
} as const;