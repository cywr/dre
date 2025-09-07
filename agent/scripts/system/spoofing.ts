import { Logger } from "../../utils/logger";
import Java from "frida-java-bridge";

enum NetworkType {
    UNKNOWN = 0,
    GPRS = 1,
    EDGE = 2,
    UMTS = 3,
    CDMA = 4,
    EVDO_0 = 5,
    EVDO_A = 6,
    RTT1x = 7,
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
}

/**
 * Comprehensive spoofing hooks to bypass detection and emulate real device characteristics.
 */
export namespace Spoofing {
    const NAME = "[Spoofing]";
    const log = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    // Spoofed device configuration
    const spoofedDevice = {
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

    const spoofedVersion = {
        RELEASE: "11",
        SDK_INT: 30,
        CODENAME: "REL",
        INCREMENTAL: "G975FXXU8DUG1",
        SECURITY_PATCH: "2021-07-01"
    };

    const spoofedTelephony = {
        mcc: "310",
        mnc: "260",
        operatorName: "T-Mobile",
        countryIso: "us",
        simState: 5,
        networkType: 13
    };

    const spoofedLocation = {
        latitude: 40.7128,
        longitude: -74.0060,
        altitude: 10.0,
        accuracy: 5.0,
        provider: "gps"
    };

    const spoofedBattery = {
        level: 75,
        status: 2, // BATTERY_STATUS_CHARGING
        scale: 100,
        plugType: 1 // BATTERY_PLUGGED_AC
    };

    function info(): void {
        Logger.log(
            Logger.Type.Debug,
            NAME, `LogType: Verbose`
            + `\n╓─┬\x1b[31m Java Classes \x1b[0m`
            + `\n║ ├─┬\x1b[35m android.os.Build \x1b[0m`
            + `\n║ │ ├── getRadioVersion`
            + `\n║ │ ├── getSerial`
            + `\n║ │ └── [Static Fields]`
            + `\n║ ├─┬\x1b[35m java.lang.System \x1b[0m`
            + `\n║ │ └── getProperty`
            + `\n║ ├─┬\x1b[35m android.net.ConnectivityManager \x1b[0m`
            + `\n║ │ └── getMobileDataEnabled`
            + `\n║ ├─┬\x1b[35m android.net.NetworkInfo \x1b[0m`
            + `\n║ │ ├── getType`
            + `\n║ │ ├── getTypeName`
            + `\n║ │ └── getSubtype`
            + `\n║ ├─┬\x1b[35m android.net.wifi.WifiInfo \x1b[0m`
            + `\n║ │ ├── getSSID`
            + `\n║ │ ├── getBSSID`
            + `\n║ │ └── getMacAddress`
            + `\n║ ├─┬\x1b[35m java.net.InetAddress \x1b[0m`
            + `\n║ │ ├── getHostAddress`
            + `\n║ │ └── getHostName`
            + `\n║ ├─┬\x1b[35m android.telephony.TelephonyManager \x1b[0m`
            + `\n║ │ ├── getNetworkType`
            + `\n║ │ ├── getNetworkOperator`
            + `\n║ │ ├── getNetworkOperatorName`
            + `\n║ │ ├── getNetworkCountryIso`
            + `\n║ │ └── getSimCountryIso`
            + `\n║ ├─┬\x1b[35m android.location.LocationManager \x1b[0m`
            + `\n║ │ └── isProviderEnabled`
            + `\n║ ├─┬\x1b[35m android.location.Location \x1b[0m`
            + `\n║ │ ├── getLatitude`
            + `\n║ │ ├── getLongitude`
            + `\n║ │ ├── getAltitude`
            + `\n║ │ ├── getAccuracy`
            + `\n║ │ └── getProvider`
            + `\n║ ├─┬\x1b[35m android.hardware.Sensor \x1b[0m`
            + `\n║ │ ├── getName`
            + `\n║ │ ├── getVendor`
            + `\n║ │ └── toString`
            + `\n║ ├─┬\x1b[35m android.media.MediaDrm \x1b[0m`
            + `\n║ │ └── getPropertyString`
            + `\n║ ├─┬\x1b[35m android.webkit.WebView \x1b[0m`
            + `\n║ │ └── getUserAgentString`
            + `\n║ ├─┬\x1b[35m android.content.Intent \x1b[0m`
            + `\n║ │ ├── getIntExtra`
            + `\n║ │ └── resolveActivity`
            + `\n║ ├─┬\x1b[35m android.content.res.Resources \x1b[0m`
            + `\n║ │ ├── getConfiguration`
            + `\n║ │ ├── getDisplayMetrics`
            + `\n║ │ └── getString`
            + `\n║ ├─┬\x1b[35m android.content.ContentResolver \x1b[0m`
            + `\n║ │ └── query`
            + `\n║ ├─┬\x1b[35m android.provider.Settings$Secure \x1b[0m`
            + `\n║ │ ├── getString`
            + `\n║ │ └── getInt`
            + `\n║ ├─┬\x1b[35m android.app.ContextImpl \x1b[0m`
            + `\n║ │ ├── checkSelfPermission`
            + `\n║ │ └── checkPermission`
            + `\n║ └─┬\x1b[35m java.util.UUID \x1b[0m`
            + `\n║   └── randomUUID`
        + `\n╙────────────────────────────────────────────────────┘`
        );
    }

    export function performNow(): void {
        info();
        try {
            buildHooks();
            systemHooks();
            networkHooks();
            telephonyHooks();
            locationSensorHooks();
            mediaHooks();
            intentHooks();
            resourcesHooks();
            contentResolverHooks();
            settingsSecureHooks();
            settingsGlobalHooks();
            contextHooks();
            runtimeHooks();
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hooks failed: \n${error}`);
        }
    }

    // Java classes
    const Build = Java.use("android.os.Build");
    const BuildVersion = Java.use("android.os.Build$VERSION");
    const SystemClass = Java.use("java.lang.System");
    const ConnectivityManager = Java.use("android.net.ConnectivityManager");
    const NetworkInfo = Java.use("android.net.NetworkInfo");
    const WifiInfo = Java.use("android.net.wifi.WifiInfo");
    const InetAddress = Java.use("java.net.InetAddress");
    const TelephonyManager = Java.use("android.telephony.TelephonyManager");
    const LocationManager = Java.use("android.location.LocationManager");
    const Location = Java.use("android.location.Location");
    const Sensor = Java.use("android.hardware.Sensor");
    const MediaDrm = Java.use("android.media.MediaDrm");
    const WebView = Java.use("android.webkit.WebView");
    const Intent = Java.use("android.content.Intent");
    const Resources = Java.use("android.content.res.Resources");
    const ResourcesImpl = Java.use("android.content.res.ResourcesImpl");
    const ContentResolver = Java.use("android.content.ContentResolver");
    const SettingsSecure = Java.use("android.provider.Settings$Secure");
    const SettingsGlobal = Java.use("android.provider.Settings$Global");
    const ContextImpl = Java.use("android.app.ContextImpl");
    const UUID = Java.use("java.util.UUID");

    /**
     * Build and system property spoofing
     */
    function buildHooks() {
        try {
            // Hook Build static fields
            for (const [key, value] of Object.entries(spoofedDevice)) {
                if (key === "ANDROID_ID" || key === "GSF_ID") continue; // These are handled elsewhere
                try {
                    Build[key].value = value;
                    log(`Build.${key} spoofed to: ${value}`);
                } catch (error) {
                    log(`Failed to spoof Build.${key}: ${error}`);
                }
            }

            // Hook VERSION static fields
            for (const [key, value] of Object.entries(spoofedVersion)) {
                try {
                    BuildVersion[key].value = value;
                    log(`Build.VERSION.${key} spoofed to: ${value}`);
                } catch (error) {
                    log(`Failed to spoof Build.VERSION.${key}: ${error}`);
                }
            }

            // Hook Build methods
            Build.getRadioVersion.implementation = function () {
                const ret = this.getRadioVersion();
                log(`Build.getRadioVersion: ${ret} -> ${spoofedDevice.RADIO}`);
                return spoofedDevice.RADIO;
            };

            Build.getSerial.implementation = function () {
                const ret = this.getSerial();
                log(`Build.getSerial: ${ret} -> ${spoofedDevice.SERIAL}`);
                return spoofedDevice.SERIAL;
            };
        } catch (error) {
            log(`Build hooks failed: ${error}`);
        }
    }

    /**
     * System property spoofing
     */
    function systemHooks() {
        try {
            SystemClass.getProperty.overload("java.lang.String").implementation = function (key: string) {
                const ret = this.getProperty(key);

                switch (key) {
                    case "ro.build.fingerprint":
                        log(`System.getProperty: ${key} -> ${spoofedDevice.FINGERPRINT}`);
                        return spoofedDevice.FINGERPRINT;
                    case "ro.build.version.release":
                        log(`System.getProperty: ${key} -> ${spoofedVersion.RELEASE}`);
                        return spoofedVersion.RELEASE;
                    case "ro.product.model":
                        log(`System.getProperty: ${key} -> ${spoofedDevice.MODEL}`);
                        return spoofedDevice.MODEL;
                    case "ro.product.brand":
                        log(`System.getProperty: ${key} -> ${spoofedDevice.BRAND}`);
                        return spoofedDevice.BRAND;
                    case "ro.product.manufacturer":
                        log(`System.getProperty: ${key} -> ${spoofedDevice.MANUFACTURER}`);
                        return spoofedDevice.MANUFACTURER;
                    case "ro.hardware":
                        log(`System.getProperty: ${key} -> ${spoofedDevice.HARDWARE}`);
                        return spoofedDevice.HARDWARE;
                    default:
                        return ret;
                }
            };

            SystemClass.getProperty.overload("java.lang.String", "java.lang.String").implementation = function (key: string, defaultValue: string) {
                const ret = this.getProperty(key, defaultValue);

                switch (key) {
                    case "ro.build.fingerprint":
                        return spoofedDevice.FINGERPRINT;
                    case "ro.build.version.release":
                        return spoofedVersion.RELEASE;
                    case "ro.product.model":
                        return spoofedDevice.MODEL;
                    case "ro.product.brand":
                        return spoofedDevice.BRAND;
                    case "ro.product.manufacturer":
                        return spoofedDevice.MANUFACTURER;
                    case "ro.hardware":
                        return spoofedDevice.HARDWARE;
                    default:
                        return ret;
                }
            };
        } catch (error) {
            log(`System hooks failed: ${error}`);
        }
    }

    /**
     * Network and connectivity spoofing
     */
    function networkHooks() {
        try {
            // ConnectivityManager
            ConnectivityManager.getMobileDataEnabled.implementation = function () {
                const ret = this.getMobileDataEnabled();
                log(`ConnectivityManager.getMobileDataEnabled: ${ret} -> true`);
                return true;
            };

            // NetworkInfo
            NetworkInfo.getType.implementation = function () {
                const ret = this.getType();
                log(`NetworkInfo.getType: ${ret} -> 1 (WIFI)`);
                return 1;
            };

            NetworkInfo.getTypeName.implementation = function () {
                const ret = this.getTypeName();
                log(`NetworkInfo.getTypeName: ${ret} -> WIFI`);
                return "WIFI";
            };

            NetworkInfo.getSubtype.implementation = function () {
                const ret = this.getSubtype();
                log(`NetworkInfo.getSubtype: ${ret} -> -1`);
                return -1;
            };

            // WifiInfo
            WifiInfo.getSSID.implementation = function () {
                const ret = this.getSSID();
                log(`WifiInfo.getSSID: ${ret} -> "AndroidWifi"`);
                return '"AndroidWifi"';
            };

            WifiInfo.getBSSID.implementation = function () {
                const ret = this.getBSSID();
                log(`WifiInfo.getBSSID: ${ret} -> 02:00:00:00:00:00`);
                return "02:00:00:00:00:00";
            };

            WifiInfo.getMacAddress.implementation = function () {
                const ret = this.getMacAddress();
                log(`WifiInfo.getMacAddress: ${ret} -> 02:00:00:00:00:00`);
                return "02:00:00:00:00:00";
            };

            // InetAddress
            InetAddress.getHostAddress.implementation = function () {
                const ret = this.getHostAddress();
                if (ret !== "127.0.0.1" && !ret.startsWith("192.168.") && !ret.startsWith("10.") && !ret.startsWith("172.")) {
                    log(`InetAddress.getHostAddress: ${ret} -> 8.8.8.8`);
                    return "8.8.8.8";
                }
                return ret;
            };

            InetAddress.getHostName.implementation = function () {
                const ret = this.getHostName();
                const address = this.getHostAddress();
                if (address !== "127.0.0.1" && !address.startsWith("192.168.") && !address.startsWith("10.") && !address.startsWith("172.")) {
                    log(`InetAddress.getHostName: ${ret} -> dns.google`);
                    return "dns.google";
                }
                return ret;
            };
        } catch (error) {
            log(`Network hooks failed: ${error}`);
        }
    }

    /**
     * Telephony and carrier spoofing
     */
    function telephonyHooks() {
        const operator = spoofedTelephony.mcc + spoofedTelephony.mnc;

        try {
            // Network types
            TelephonyManager.getNetworkType.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getNetworkType(...args);
                    log(`TelephonyManager.getNetworkType: ${ret} -> ${spoofedTelephony.networkType}`);
                    return spoofedTelephony.networkType;
                };
            });

            // Operators
            TelephonyManager.getNetworkOperator.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getNetworkOperator(...args);
                    log(`TelephonyManager.getNetworkOperator: ${ret} -> ${operator}`);
                    return operator;
                };
            });

            TelephonyManager.getNetworkOperatorName.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getNetworkOperatorName(...args);
                    log(`TelephonyManager.getNetworkOperatorName: ${ret} -> ${spoofedTelephony.operatorName}`);
                    return spoofedTelephony.operatorName;
                };
            });

            TelephonyManager.getNetworkCountryIso.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getNetworkCountryIso(...args);
                    log(`TelephonyManager.getNetworkCountryIso: ${ret} -> ${spoofedTelephony.countryIso}`);
                    return spoofedTelephony.countryIso;
                };
            });

            TelephonyManager.getSimCountryIso.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getSimCountryIso(...args);
                    log(`TelephonyManager.getSimCountryIso: ${ret} -> ${spoofedTelephony.countryIso}`);
                    return spoofedTelephony.countryIso;
                };
            });
        } catch (error) {
            log(`Telephony hooks failed: ${error}`);
        }
    }

    /**
     * Location and sensor spoofing
     */
    function locationSensorHooks() {
        try {
            // LocationManager
            LocationManager.isProviderEnabled.overload("java.lang.String").implementation = function (provider: string) {
                const ret = this.isProviderEnabled(provider);
                if (provider === "gps" || provider === "network") {
                    log(`LocationManager.isProviderEnabled: ${provider} -> true`);
                    return true;
                }
                return ret;
            };

            // Location coordinates
            Location.getLatitude.implementation = function () {
                const ret = this.getLatitude();
                log(`Location.getLatitude: ${ret} -> ${spoofedLocation.latitude}`);
                return spoofedLocation.latitude;
            };

            Location.getLongitude.implementation = function () {
                const ret = this.getLongitude();
                log(`Location.getLongitude: ${ret} -> ${spoofedLocation.longitude}`);
                return spoofedLocation.longitude;
            };

            Location.getAltitude.implementation = function () {
                const ret = this.getAltitude();
                log(`Location.getAltitude: ${ret} -> ${spoofedLocation.altitude}`);
                return spoofedLocation.altitude;
            };

            Location.getAccuracy.implementation = function () {
                const ret = this.getAccuracy();
                log(`Location.getAccuracy: ${ret} -> ${spoofedLocation.accuracy}`);
                return spoofedLocation.accuracy;
            };

            Location.getProvider.implementation = function () {
                const ret = this.getProvider();
                log(`Location.getProvider: ${ret} -> ${spoofedLocation.provider}`);
                return spoofedLocation.provider;
            };

            // Sensor cleanup
            Sensor.getName.implementation = function () {
                const ret = this.getName();
                if (ret.includes("Goldfish")) {
                    const spoofed = ret.replace("Goldfish ", "");
                    log(`Sensor.getName: ${ret} -> ${spoofed}`);
                    return spoofed;
                }
                return ret;
            };

            Sensor.getVendor.implementation = function () {
                const ret = this.getVendor();
                if (ret.includes("The Android Open Source Project") || ret.includes("AOSP")) {
                    const spoofed = ret.replace("The Android Open Source Project", "Sensors Inc.")
                        .replace("AOSP", "Sensors Inc.");
                    log(`Sensor.getVendor: ${ret} -> ${spoofed}`);
                    return spoofed;
                }
                return ret;
            };

            (Sensor.toString as any).implementation = function () {
                const ret = this.toString();
                if (ret.includes("Goldfish") || ret.includes("The Android Open Source Project") || ret.includes("AOSP")) {
                    const spoofed = ret.replace(/Goldfish /g, "")
                        .replace(/The Android Open Source Project/g, "Sensors Inc.")
                        .replace(/AOSP/g, "Sensors Inc.");
                    log(`Sensor.toString: cleaned up sensor description`);
                    return spoofed;
                }
                return ret;
            };
        } catch (error) {
            log(`Location/Sensor hooks failed: ${error}`);
        }
    }

    /**
     * Media and WebView spoofing
     */
    function mediaHooks() {
        try {
            // MediaDrm
            MediaDrm.getPropertyString.implementation = function (propertyName: string) {
                const ret = this.getPropertyString(propertyName);

                switch (propertyName) {
                    case "vendor":
                        log(`MediaDrm.getPropertyString: ${propertyName} -> Samsung`);
                        return "Samsung";
                    case "version":
                        log(`MediaDrm.getPropertyString: ${propertyName} -> 1.4`);
                        return "1.4";
                    case "description":
                        log(`MediaDrm.getPropertyString: ${propertyName} -> Samsung Exynos DRM`);
                        return "Samsung Exynos DRM";
                    case "deviceUniqueId":
                        log(`MediaDrm.getPropertyString: ${propertyName} -> 0123456789abcdef`);
                        return "0123456789abcdef";
                    default:
                        return ret;
                }
            };

            // WebView User-Agent
            WebView.getUserAgentString.overload("android.content.Context").implementation = function (context: any) {
                const ret = this.getUserAgentString(context);
                if (ret.includes("Android SDK built for x86") || ret.includes("Emulator") || ret.includes("generic")) {
                    const spoofedUA = "Mozilla/5.0 (Linux; Android 11; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36";
                    log(`WebView.getUserAgentString: spoofed emulator UA`);
                    return spoofedUA;
                }
                return ret;
            };

            WebView.getUserAgentString.overload().implementation = function () {
                const ret = this.getUserAgentString();
                if (ret.includes("Android SDK built for x86") || ret.includes("Emulator") || ret.includes("generic")) {
                    const spoofedUA = "Mozilla/5.0 (Linux; Android 11; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36";
                    log(`WebView.getUserAgentString: spoofed emulator UA`);
                    return spoofedUA;
                }
                return ret;
            };
        } catch (error) {
            log(`Media hooks failed: ${error}`);
        }
    }

    /**
     * Intent hooks for battery spoofing and monitoring
     */
    function intentHooks() {
        try {
            // Battery status spoofing
            Intent.getIntExtra.overload("java.lang.String", "int").implementation = function (name: string, defaultValue: number) {
                const ret = this.getIntExtra(name, defaultValue);
                const action = this.getAction();

                if (action === "android.intent.action.BATTERY_CHANGED") {
                    switch (name) {
                        case "level":
                            log(`Intent[BATTERY_CHANGED].getIntExtra: ${name} -> ${spoofedBattery.level}`);
                            return spoofedBattery.level;
                        case "status":
                            log(`Intent[BATTERY_CHANGED].getIntExtra: ${name} -> ${spoofedBattery.status}`);
                            return spoofedBattery.status;
                        case "scale":
                            log(`Intent[BATTERY_CHANGED].getIntExtra: ${name} -> ${spoofedBattery.scale}`);
                            return spoofedBattery.scale;
                        case "plugged":
                            log(`Intent[BATTERY_CHANGED].getIntExtra: ${name} -> ${spoofedBattery.plugType}`);
                            return spoofedBattery.plugType;
                    }
                }

                return ret;
            };

            // Intent monitoring
            Intent.resolveActivity.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    try {
                        const action = this.getAction();
                        const pkg = this.getPackage();
                        const data = this.getDataString();

                        if (action || pkg || data) {
                            log(`Intent.resolveActivity: ${action || 'no-action'} | ${pkg || 'no-pkg'} | ${data || 'no-data'}`);
                        }
                    } catch (error) {
                        log(`Intent.resolveActivity monitoring error: ${error}`);
                    }
                    return this.resolveActivity(...args);
                };
            });
        } catch (error) {
            log(`Intent hooks failed: ${error}`);
        }
    }

    /**
     * Resources and display spoofing
     */
    function resourcesHooks() {
        try {
            // Configuration spoofing for MCC/MNC
            Resources.getConfiguration.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const ret = this.getConfiguration(...args);

                    const oldMcc = ret.mcc.value;
                    const newMcc = parseInt(spoofedTelephony.mcc);
                    ret.mcc.value = newMcc;
                    log(`Resources.getConfiguration: mcc ${oldMcc} -> ${newMcc}`);

                    const oldMnc = ret.mnc.value;
                    const newMnc = parseInt(spoofedTelephony.mnc);
                    ret.mnc.value = newMnc;
                    log(`Resources.getConfiguration: mnc ${oldMnc} -> ${newMnc}`);

                    return ret;
                };
            });

            // Display metrics spoofing (Galaxy S10)
            Resources.getDisplayMetrics.implementation = function () {
                const ret = this.getDisplayMetrics();
                try {
                    ret.density.value = 3.0;
                    ret.densityDpi.value = 480;
                    ret.widthPixels.value = 1440;
                    ret.heightPixels.value = 3040;
                    ret.scaledDensity.value = 3.0;
                    ret.xdpi.value = 480.0;
                    ret.ydpi.value = 480.0;
                    log(`Resources.getDisplayMetrics: spoofed to Galaxy S10 metrics`);
                } catch (error) {
                    log(`Failed to spoof display metrics: ${error}`);
                }
                return ret;
            };

            ResourcesImpl.getDisplayMetrics.implementation = function () {
                const ret = this.getDisplayMetrics();
                try {
                    ret.density.value = 3.0;
                    ret.densityDpi.value = 480;
                    ret.widthPixels.value = 1440;
                    ret.heightPixels.value = 3040;
                    ret.scaledDensity.value = 3.0;
                    ret.xdpi.value = 480.0;
                    ret.ydpi.value = 480.0;
                    log(`ResourcesImpl.getDisplayMetrics: spoofed to Galaxy S10 metrics`);
                } catch (error) {
                    log(`Failed to spoof impl display metrics: ${error}`);
                }
                return ret;
            };

            // String monitoring
            Resources.getString.overload("int").implementation = function (id: number) {
                const ret = this.getString(id);
                if (ret && (ret.includes("emulator") || ret.includes("goldfish") || ret.includes("generic"))) {
                    log(`Resources.getString: potentially revealing string: ${ret}`);
                }
                return ret;
            };
        } catch (error) {
            log(`Resources hooks failed: ${error}`);
        }
    }

    /**
     * ContentResolver hooks for GSF ID spoofing
     */
    function contentResolverHooks() {
        try {
            const MatrixCursor = Java.use("android.database.MatrixCursor");

            ContentResolver.query.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const result = this.query(...args);

                    try {
                        if (args[0].toString() === "content://com.google.android.gsf.gservices" && args[3] === "android_id") {
                            const gsfidHex = spoofedDevice.GSF_ID;
                            const gsfidDec = BigInt("0x" + gsfidHex);
                            const strArray = Java.array("java.lang.String", ["key", "value"]);
                            const objArray = Java.array("Ljava.lang.Object;", ["android_id", gsfidDec.toString()]);
                            const customCursor = MatrixCursor.$new(strArray);
                            customCursor.addRow(objArray);
                            log(`ContentResolver.query: spoofed GSF ID to ${gsfidHex} (${gsfidDec})`);
                            return customCursor;
                        }
                    } catch (error) {
                        log(`ContentResolver.query error: ${error}`);
                    }

                    return result;
                };
            });
        } catch (error) {
            log(`ContentResolver hooks failed: ${error}`);
        }
    }

    /**
     * Settings.Secure hooks for Android ID and development settings
     */
    function settingsSecureHooks() {
        try {
            // getString hooks
            SettingsSecure.getString.overload("android.content.ContentResolver", "java.lang.String").implementation = function (cr: any, name: string) {
                const ret = this.getString(cr, name);

                switch (name) {
                    case "android_id":
                        log(`Settings.Secure.getString: ${name} -> ${spoofedDevice.ANDROID_ID}`);
                        return spoofedDevice.ANDROID_ID;
                    case "mock_location":
                        log(`Settings.Secure.getString: ${name} -> 0`);
                        return "0";
                    default:
                        return ret;
                }
            };

            // getInt hooks
            SettingsSecure.getInt.overload("android.content.ContentResolver", "java.lang.String", "int").implementation = function (cr: any, name: string, defaultValue: number) {
                const ret = this.getInt(cr, name, defaultValue);

                switch (name) {
                    case "auto_time":
                        log(`Settings.Secure.getInt: ${name} -> 1`);
                        return 1;
                    case "development_settings_enabled":
                    case "adb_enabled":
                    case "airplane_mode_on":
                        log(`Settings.Secure.getInt: ${name} -> 0`);
                        return 0;
                    default:
                        return ret;
                }
            };
        } catch (error) {
            log(`Settings.Secure hooks failed: ${error}`);
        }
    }

    /**
     * Settings.Global hooks for system-wide settings
     */
    function settingsGlobalHooks() {
        try {
            SettingsGlobal.getInt.overload("android.content.ContentResolver", "java.lang.String", "int").implementation = function (cr: any, name: string, number: number) {
                const ret = this.getInt(cr, name, number);

                switch (name) {
                    case "development_settings_enabled":
                        log(`Settings.Global.getInt: ${name} -> 0`);
                        return 0;
                    case "airplane_mode_on":
                        log(`Settings.Global.getInt: ${name} -> 0`);
                        return 0;
                    case "mobile_data":
                        log(`Settings.Global.getInt: ${name} -> 1`);
                        return 1;
                    default:
                        return ret;
                }
            };
        } catch (error) {
            log(`Settings.Global hooks failed: ${error}`);
        }
    }

    /**
     * Context permission checks
     */
    function contextHooks() {
        try {
            ContextImpl.checkSelfPermission.overload("java.lang.String").implementation = function (permission: string) {
                const result = this.checkSelfPermission(permission);
                log(`Context.checkSelfPermission: ${permission} -> ${result}`);
                return result;
            };

            ContextImpl.checkPermission.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const result = this.checkPermission(...args);
                    log(`Context.checkPermission: ${args[0]} -> ${result}`);
                    return result;
                };
            });
        } catch (error) {
            log(`Context hooks failed: ${error}`);
        }
    }

    /**
     * Runtime utilities
     */
    function runtimeHooks() {
        try {
            // UUID monitoring
            UUID.randomUUID.implementation = function () {
                const ret = this.randomUUID();
                log(`UUID.randomUUID: generated`);
                return ret;
            };
        } catch (error) {
            log(`Runtime hooks failed: ${error}`);
        }
    }
}