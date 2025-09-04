import { Logger } from "../../utils/logger";
import { Hook } from "../../interfaces/hook";
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
 * Perform hooks on the system to bypass anti-debug validations.
*/
export class DeviceCloaking extends Hook {
    NAME = "[Device Cloaking]";
    LOG_TYPE = Logger.Type.Debug;

    private SettingsGlobal = Java.use("android.provider.Settings$Global");
    private SettingsSecure = Java.use("android.provider.Settings$Secure");
    private ContentResolver = Java.use('android.content.ContentResolver');
    private Location = Java.use("android.location.Location");
    private TelephonyManager = Java.use('android.telephony.TelephonyManager');
    private ConnectivityManager = Java.use("android.net.ConnectivityManager");

    info(): void {
        Logger.log(
            Logger.Type.Debug,
            this.NAME, `LogType: Debug`
            + `\n╓─┬\x1b[31m Java Classes \x1b[0m`
            + `\n║ ├─┬\x1b[35m android.provider.Settings$Global \x1b[0m`
            + `\n║ │ └── getInt`
            + `\n║ ├─┬\x1b[35m android.provider.Settings$Secure \x1b[0m`
            + `\n║ │ ├── getString`
            + `\n║ │ └── getInt`
            + `\n║ ├─┬\x1b[35m android.content.ContentResolver \x1b[0m`
            + `\n║ │ └── query`
            + `\n║ ├─┬\x1b[35m android.location.Location \x1b[0m`
            + `\n║ │ └── isFromMockProvider`
            + `\n║ ├─┬\x1b[35m android.telephony.TelephonyManager \x1b[0m`
            + `\n║ │ ├── getLine1Number`
            + `\n║ │ ├── getSubscriberId`
            + `\n║ │ ├── getDeviceId`
            + `\n║ │ ├── getImei`
            + `\n║ │ ├── getMeid`
            + `\n║ │ ├── getSimOperator`
            + `\n║ │ └── getNetworkType`
            + `\n║ ├─┬\x1b[35m android.net.ConnectivityManager \x1b[0m`
            + `\n║ │ └── getMobileDataEnabled`
        + `\n╙────────────────────────────────────────────────────┘`
        );
    }

    execute(): void {
        this.info()
        try {
            this.build()
            this.system()
            this.systemProperties()
            this.settingsGlobal()
            this.settingsSecure()
            this.googleServices()
            this.location()
            this.telephonyManager()
            this.connectivityManager()
        } catch (error) {
            Logger.log(Logger.Type.Error, this.NAME, `Hooks failed: \n${error}`);
        }
    }

    /**
    * Preventing application from 
    */
    build() {

    }

    /**
    * Preventing application from 
    */
    system() {

    }

    /**
    * Preventing application from 
    */
    systemProperties() {

    }

    /**
    * android.provider.Settings$Global
    */
    settingsGlobal() {
        const log = this.log;
        
        this.SettingsGlobal.getInt.overload("android.content.ContentResolver", "java.lang.String", "int").implementation = function (cr: any, name: string, number: number) {
            switch (name) {
                case "development_settings_enabled":
                    log(`SettingsGlobal.getInt: development_settings_enabled -> 0`)
                    return 0;
                case "airplane_mode_on":
                    log(`SettingsGlobal.getInt: airplane_mode_on -> 0`)
                    return 0;
                case "mobile_data":
                    log(`SettingsGlobal.getInt: mobile_data -> 1`)
                    return 1;
                default:
                    break;
            }
            return this.getInt(cr, name, number);
        };
    }

    /**
    * android.provider.Settings$Secure
    */
    settingsSecure() {
        const log = this.log;
        
        this.SettingsSecure.getString.overload("android.content.ContentResolver", "java.lang.String").implementation = function (cr: any, name: string) {
            switch (name) {
                case "android_id":
                    log(`SettingsSecure.getString: android_id -> "2fc4b5912826ad1"`)
                    return "2fc4b5912826ad1"
                case "mock_location":
                    log(`SettingsSecure.getString: mock_location -> "0"`)
                    return "0"
                default:
                    break
            }
            return this.getString(cr, name);
        };

        this.SettingsSecure.getInt.overload("android.content.ContentResolver", "java.lang.String", "int").implementation = function (cr: any, name: string, number: number) {
            switch (name) {
                case "development_settings_enabled":
                    log(`SettingsSecure.getInt: development_settings_enabled -> 0`)
                    return 0
                case "adb_enabled":
                    log(`SettingsSecure.getInt: adb_enabled -> 0`)
                    return 0
                case "airplane_mode_on":
                    log(`SettingsSecure.getInt: airplane_mode_on -> 0`)
                    return 0
                case "mobile_data":
                    log(`SettingsSecure.getInt: mobile_data -> 1`)
                    return 1
                default:
                    break;
            }
            return this.getInt(cr, name, number);
        };
    }

    /**
    * android.content.ContentResolver
    * 
    * Preventing application from retrieving information about Google Services
    */
    googleServices() {
        const log = this.log;
        
        this.ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'android.os.Bundle', 'android.os.CancellationSignal').implementation = function (uri: any, str: any, bundle: any, sig: any) {
            if (uri == 'content://com.google.android.gsf.gservicesa') {
                log(`ContentResolver.query: com.google.android.gsf.gservicesa -> null`)
                return null;
            } else
                return this.query(uri, str, bundle, sig);
        }

        this.ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function (uri: any, astr: any, bstr: any, cstr: any, dstr: any) {
            if (uri == 'content://com.google.android.gsf.gservicesa') {
                log(`ContentResolver.query: com.google.android.gsf.gservicesa -> null`)
                return null;
            } else
                return this.query(uri, astr, bstr, cstr, dstr);
        }

        this.ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'android.os.CancellationSignal').implementation = function (uri: any, astr: any, bstr: any, cstr: any, sig: any) {
            if (uri == 'content://com.google.android.gsf.gservicesa') {
                log(`ContentResolver.query: com.google.android.gsf.gservicesa -> null`)
                return null;
            } else
                return this.query(uri, astr, bstr, cstr, sig);
        }
    }

    /**
    * android.location.Location
    */
    location() {
        const log = this.log;
        
        this.Location.isFromMockProvider.overload().implementation = function () {
            log(`Location.isFromMockProvider: false`)
            return false
        };
    }

    /**
    * android.telephony.TelephonyManager
    */
    telephonyManager() {
        const log = this.log;
        
        // Hook all overloads of getLine1Number
        this.TelephonyManager.getLine1Number.overloads.forEach((overload: any) => {
            overload.implementation = function () {
                log(`TelephonyManager.getLine1Number: 1234567890`)
                return "1234567890";
            }
        });

        // Hook all overloads of getSubscriberId
        this.TelephonyManager.getSubscriberId.overloads.forEach((overload: any) => {
            overload.implementation = function () {
                log(`TelephonyManager.getSubscriberId: 1234567890`)
                return "1234567890";
            }
        });

        // Hook all overloads of getDeviceId
        this.TelephonyManager.getDeviceId.overloads.forEach((overload: any) => {
            overload.implementation = function () {
                log(`TelephonyManager.getDeviceId: 1234567890`)
                return "1234567890";
            }
        });

        // Hook all overloads of getImei
        this.TelephonyManager.getImei.overloads.forEach((overload: any) => {
            overload.implementation = function () {
                log(`TelephonyManager.getImei: 1234567890`)
                return "1234567890";
            }
        });

        // Hook all overloads of getMeid
        this.TelephonyManager.getMeid.overloads.forEach((overload: any) => {
            overload.implementation = function () {
                log(`TelephonyManager.getMeid: 1234567890`)
                return "1234567890";
            }
        });

        // Hook all overloads of getSimOperator
        this.TelephonyManager.getSimOperator.overloads.forEach((overload: any) => {
            overload.implementation = function () {
                log(`TelephonyManager.getSimOperator: 0000`)
                return "0000";
            }
        });

        // Hook all overloads of getNetworkType
        this.TelephonyManager.getNetworkType.overloads.forEach((overload: any) => {
            overload.implementation = function () {
                log(`TelephonyManager.getNetworkType: LTE`)
                return NetworkType.LTE;
            }
        });
    }

    /**
    * android.net.ConnectivityManager
    */
    connectivityManager() {
        const log = this.log;
        
        this.ConnectivityManager.getMobileDataEnabled.overload().implementation = function () {
            log(`ConnectivityManager.getMobileDataEnabled: true`)
            return true
        };
    }
}
