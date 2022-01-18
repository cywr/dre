import { Logger } from "../../utils/logger";

export namespace DeviceCloaking {
    const NAME = "[Device Cloaking]";

    export enum NetworkType {
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
     * 
     */
    export function hook() {
        Logger.log(Logger.Type.Config, NAME, "Hooks loaded.");
        try {
            build()
            system()
            systemProperties()
            settingsGlobal()
            settingsSecure()
            googleServices()
            location()
            telephonyManager()
            connectivityManager()
        } catch(error) {
            Logger.log(Logger.Type.Error, NAME, `Hooks failed.\n${error}`);
        }
    }

    /**
    * Preventing application from 
    */
     function build() {

    }

    /**
    * Preventing application from 
    */
     function system() {

    }

    /**
    * Preventing application from 
    */
     function systemProperties() {

    }

    
    /**
    * android.provider.Settings$Global
    */
     function settingsGlobal() {
        const SettingsGlobal = Java.use("android.provider.Settings$Global");

        //getInt
        SettingsGlobal.getInt.overload("android.content.ContentResolver", "java.lang.String", "int").implementation = function(cr: any, name: string, number: number) {
            switch (name) {
                case "development_settings_enabled":
                    Logger.log(Logger.Type.Hook, NAME, `SettingsGlobal.getInt: development_settings_enabled -> 0`)
                    return 0;
                case "airplane_mode_on":
                    Logger.log(Logger.Type.Hook, NAME, `SettingsGlobal.getInt: airplane_mode_on -> 0`)
                    return 0;
                case "mobile_data":
                    Logger.log(Logger.Type.Hook, NAME, `SettingsGlobal.getInt: mobile_data -> 1`)
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
     function settingsSecure() {
         const SettingsSecure = Java.use("android.provider.Settings$Secure");

        //getString
        SettingsSecure.getString.overload("android.content.ContentResolver", "java.lang.String").implementation = function (cr: any, name: string) {
            switch(name) {
                case "android_id":
                    Logger.log(Logger.Type.Hook, NAME, `SettingsSecure.getString: android_id -> "2fc4b5912826ad1"`)
                    return "2fc4b5912826ad1"
                case "mock_location":
                    Logger.log(Logger.Type.Hook, NAME, `SettingsSecure.getString: mock_location -> "0"`)
                    return "0"
                default:
                    break
            }
            return this.getString(cr, name);
        };

        //getInt
        SettingsSecure.getInt.overload("android.content.ContentResolver", "java.lang.String", "int").implementation = function (cr: any, name: string, number: number) {
            switch (name) {
                case "development_settings_enabled":
                    Logger.log(Logger.Type.Hook, NAME, `SettingsSecure.getInt: development_settings_enabled -> 0`)
                    return 0
                case "adb_enabled":
                    Logger.log(Logger.Type.Hook, NAME, `SettingsSecure.getInt: adb_enabled -> 0`)
                    return 0
                case "airplane_mode_on":
                    Logger.log(Logger.Type.Hook, NAME, `SettingsSecure.getInt: airplane_mode_on -> 0`)
                    return 0
                case "mobile_data":
                    Logger.log(Logger.Type.Hook, NAME, `SettingsSecure.getInt: mobile_data -> 1`)
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
    * Preventing application from retriveing information about Google Services
    */
     function googleServices() {
        var ContentResolver = Java.use('android.content.ContentResolver');

        ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'android.os.Bundle', 'android.os.CancellationSignal').implementation = function(uri:any, str:any, bundle:any, sig:any){
            if(uri == 'content://com.google.android.gsf.gservicesa') {
                Logger.log(Logger.Type.Hook, NAME, `ContentResolver.query: com.google.android.gsf.gservicesa -> null`)
                return null;
            } else 
                return this.query(uri,str,bundle,sig);
        }
        
        ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function(uri:any, astr:any, bstr:any, cstr:any, dstr:any) {
            if(uri == 'content://com.google.android.gsf.gservicesa') {
                Logger.log(Logger.Type.Hook, NAME, `ContentResolver.query: com.google.android.gsf.gservicesa -> null`)
                return null;
            } else
                return this.query(uri,astr,bstr,cstr,dstr);
        }
        
        ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'android.os.CancellationSignal').implementation = function(uri:any, astr:any, bstr:any, cstr:any, sig:any){
            if(uri == 'content://com.google.android.gsf.gservicesa') {
                Logger.log(Logger.Type.Hook, NAME, `ContentResolver.query: com.google.android.gsf.gservicesa -> null`)
                return null;
            } else 
                return this.query(uri,astr,bstr,cstr,sig);
        }
    }

    /**
    * android.location.Location
    */
    function location() {
        const location = Java.use("android.location.Location");

        location.isFromMockProvider.overload().implementation = function () {
            Logger.log(Logger.Type.Hook, NAME, `Location.isFromMockProvider: false`)
            return false
        };
    }

    /**
    * android.telephony.TelephonyManager
    */
    function telephonyManager() {
        var TelephonyManager = Java.use('android.telephony.TelephonyManager');

        //getLine1Number
        for (let index = 0; index < TelephonyManager.getLine1Number.overloads.length; index++) {
            TelephonyManager.getLine1Number.overloads[index].implementation = function() {
                Logger.log(Logger.Type.Hook, NAME, `TelephonyManager.getLine1Number: 1234567890`)
                return "1234567890";
            }
        }
        
        //getSubscriberId
        for (let index = 0; index < TelephonyManager.getSubscriberId.overloads.length; index++) {
            TelephonyManager.getSubscriberId.overloads[index].implementation = function() {
                Logger.log(Logger.Type.Hook, NAME, `TelephonyManager.getSubscriberId: 1234567890`)
                return "1234567890";
            }
            
        }

        //getDeviceId
        for (let index = 0; index < TelephonyManager.getDeviceId.overloads.length; index++) {
            TelephonyManager.getDeviceId.overloads[index].implementation = function() {
                Logger.log(Logger.Type.Hook, NAME, `TelephonyManager.getDeviceId: 1234567890`)
                return "1234567890";
            }
        }
        
        //getImei
        for (let index = 0; index < TelephonyManager.getImei.overloads.length; index++) {
            TelephonyManager.getImei.overloads[index].implementation = function() {
                Logger.log(Logger.Type.Hook, NAME, `TelephonyManager.getImei: 1234567890`)
                return "1234567890";
            }
        }

        //getMeid
        for (let index = 0; index < TelephonyManager.getMeid.overloads.length; index++) {
            TelephonyManager.getMeid.overloads[index].implementation = function() {
                Logger.log(Logger.Type.Hook, NAME, `TelephonyManager.getMeid: 1234567890`)
                return "1234567890";
            }
        }

        //getSimOperator
        for (let index = 0; index < TelephonyManager.getSimOperator.overloads.length; index++) {
            TelephonyManager.getSimOperator.overloads[index].implementation = function() {
                Logger.log(Logger.Type.Hook, NAME, `TelephonyManager.getSimOperator: 0000`)
                return "0000";
            }
        }

        //getNetworkType
        for (let index = 0; index < TelephonyManager.getNetworkType.overloads.length; index++) {
            TelephonyManager.getNetworkType.overloads[index].implementation = function() {
                Logger.log(Logger.Type.Hook, NAME, `TelephonyManager.getNetworkType: LTE`)
                return NetworkType.LTE;
            }
        }
    }

    /**
    * android.net.ConnectivityManager
    */
     function connectivityManager() {
        const ConnectivityManager = Java.use("android.net.ConnectivityManager");

        ConnectivityManager.getMobileDataEnabled.overload().implementation = function () {
            Logger.log(Logger.Type.Hook, NAME, `ConnectivityManager.getMobileDataEnabled: true`)
            return true
      };
    }
}
