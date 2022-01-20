import { Logger } from "../../utils/logger";
import { Hook } from "../../interfaces/hook";

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
export class DeviceCloaking implements Hook {
    NAME = "[Device Cloaking]";
    LOG_TYPE = Logger.Type.Debug;

    info(): void {
        Logger.log(
            Logger.Type.Config, 
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
            this.build(this)
            this.system(this)
            this.systemProperties(this)
            this.settingsGlobal(this)
            this.settingsSecure(this)
            this.googleServices(this)
            this.location(this)
            this.telephonyManager(this)
            this.connectivityManager(this)
        } catch(error) {
            Logger.log(Logger.Type.Error, this.NAME, `Hooks failed: \n${error}`);
        }
    }

    /** Hooked classes */
    _SettingsGlobal = Java.use("android.provider.Settings$Global");
    _SettingsSecure = Java.use("android.provider.Settings$Secure");
    _ContentResolver = Java.use('android.content.ContentResolver');
    _Location = Java.use("android.location.Location");
    _TelephonyManager = Java.use('android.telephony.TelephonyManager');
    _ConnectivityManager = Java.use("android.net.ConnectivityManager");

    /**
    * Preventing application from 
    */
     build(_this: DeviceCloaking) {

    }

    /**
    * Preventing application from 
    */
     system(_this: DeviceCloaking) {

    }

    /**
    * Preventing application from 
    */
     systemProperties(_this: DeviceCloaking) {

    }

    
    /**
    * android.provider.Settings$Global
    */
     settingsGlobal(_this: DeviceCloaking) {
        //getInt
        _this._SettingsGlobal.getInt.overload("android.content.ContentResolver", "java.lang.String", "int").implementation = function(cr: any, name: string, number: number) {
            switch (name) {
                case "development_settings_enabled":
                    Logger.log(_this.LOG_TYPE, _this.NAME, `SettingsGlobal.getInt: development_settings_enabled -> 0`)
                    return 0;
                case "airplane_mode_on":
                    Logger.log(_this.LOG_TYPE, _this.NAME, `SettingsGlobal.getInt: airplane_mode_on -> 0`)
                    return 0;
                case "mobile_data":
                    Logger.log(_this.LOG_TYPE, _this.NAME, `SettingsGlobal.getInt: mobile_data -> 1`)
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
     settingsSecure(_this: DeviceCloaking) {
        //getString
        _this._SettingsSecure.getString.overload("android.content.ContentResolver", "java.lang.String").implementation = function(cr: any, name: string) {
            switch(name) {
                case "android_id":
                    Logger.log(_this.LOG_TYPE, _this.NAME, `SettingsSecure.getString: android_id -> "2fc4b5912826ad1"`)
                    return "2fc4b5912826ad1"
                case "mock_location":
                    Logger.log(_this.LOG_TYPE, _this.NAME, `SettingsSecure.getString: mock_location -> "0"`)
                    return "0"
                default:
                    break
            }
            return this.getString(cr, name);
        };

        //getInt
        _this._SettingsSecure.getInt.overload("android.content.ContentResolver", "java.lang.String", "int").implementation = function(cr: any, name: string, number: number) {
            switch (name) {
                case "development_settings_enabled":
                    Logger.log(_this.LOG_TYPE, _this.NAME, `SettingsSecure.getInt: development_settings_enabled -> 0`)
                    return 0
                case "adb_enabled":
                    Logger.log(_this.LOG_TYPE, _this.NAME, `SettingsSecure.getInt: adb_enabled -> 0`)
                    return 0
                case "airplane_mode_on":
                    Logger.log(_this.LOG_TYPE, _this.NAME, `SettingsSecure.getInt: airplane_mode_on -> 0`)
                    return 0
                case "mobile_data":
                    Logger.log(_this.LOG_TYPE, _this.NAME, `SettingsSecure.getInt: mobile_data -> 1`)
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
     googleServices(_this: DeviceCloaking) {
        _this._ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'android.os.Bundle', 'android.os.CancellationSignal').implementation = function(uri:any, str:any, bundle:any, sig:any){
            if(uri == 'content://com.google.android.gsf.gservicesa') {
                Logger.log(_this.LOG_TYPE, _this.NAME, `ContentResolver.query: com.google.android.gsf.gservicesa -> null`)
                return null;
            } else 
                return this.query(uri,str,bundle,sig);
        }
        
        _this._ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function(uri:any, astr:any, bstr:any, cstr:any, dstr:any) {
            if(uri == 'content://com.google.android.gsf.gservicesa') {
                Logger.log(_this.LOG_TYPE, _this.NAME, `ContentResolver.query: com.google.android.gsf.gservicesa -> null`)
                return null;
            } else
                return this.query(uri,astr,bstr,cstr,dstr);
        }
        
        _this._ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'android.os.CancellationSignal').implementation = function(uri:any, astr:any, bstr:any, cstr:any, sig:any){
            if(uri == 'content://com.google.android.gsf.gservicesa') {
                Logger.log(_this.LOG_TYPE, _this.NAME, `ContentResolver.query: com.google.android.gsf.gservicesa -> null`)
                return null;
            } else 
                return this.query(uri,astr,bstr,cstr,sig);
        }
    }

    /**
    * android.location.Location
    */
    location(_this: DeviceCloaking) {
        _this._Location.isFromMockProvider.overload().implementation = function() {
            Logger.log(_this.LOG_TYPE, _this.NAME, `Location.isFromMockProvider: false`)
            return false
        };
    }

    /**
    * android.telephony.TelephonyManager
    */
    telephonyManager(_this: DeviceCloaking) {
        //getLine1Number
        for (let index = 0; index < _this._TelephonyManager.getLine1Number.overloads.length; index++) {
            _this._TelephonyManager.getLine1Number.overloads[index].implementation = function() {
                Logger.log(_this.LOG_TYPE, _this.NAME, `TelephonyManager.getLine1Number: 1234567890`)
                return "1234567890";
            }
        }
        
        //getSubscriberId
        for (let index = 0; index < _this._TelephonyManager.getSubscriberId.overloads.length; index++) {
            _this._TelephonyManager.getSubscriberId.overloads[index].implementation = function() {
                Logger.log(_this.LOG_TYPE, _this.NAME, `TelephonyManager.getSubscriberId: 1234567890`)
                return "1234567890";
            }
            
        }

        //getDeviceId
        for (let index = 0; index < _this._TelephonyManager.getDeviceId.overloads.length; index++) {
            _this._TelephonyManager.getDeviceId.overloads[index].implementation = function() {
                Logger.log(_this.LOG_TYPE, _this.NAME, `TelephonyManager.getDeviceId: 1234567890`)
                return "1234567890";
            }
        }
        
        //getImei
        for (let index = 0; index < _this._TelephonyManager.getImei.overloads.length; index++) {
            _this._TelephonyManager.getImei.overloads[index].implementation = function() {
                Logger.log(_this.LOG_TYPE, _this.NAME, `TelephonyManager.getImei: 1234567890`)
                return "1234567890";
            }
        }

        //getMeid
        for (let index = 0; index < _this._TelephonyManager.getMeid.overloads.length; index++) {
            _this._TelephonyManager.getMeid.overloads[index].implementation = function() {
                Logger.log(_this.LOG_TYPE, _this.NAME, `TelephonyManager.getMeid: 1234567890`)
                return "1234567890";
            }
        }

        //getSimOperator
        for (let index = 0; index < _this._TelephonyManager.getSimOperator.overloads.length; index++) {
            _this._TelephonyManager.getSimOperator.overloads[index].implementation = function() {
                Logger.log(_this.LOG_TYPE, _this.NAME, `TelephonyManager.getSimOperator: 0000`)
                return "0000";
            }
        }

        //getNetworkType
        for (let index = 0; index < _this._TelephonyManager.getNetworkType.overloads.length; index++) {
            _this._TelephonyManager.getNetworkType.overloads[index].implementation = function() {
                Logger.log(_this.LOG_TYPE, _this.NAME, `TelephonyManager.getNetworkType: LTE`)
                return NetworkType.LTE;
            }
        }
    }

    /**
    * android.net.ConnectivityManager
    */
     connectivityManager(_this: DeviceCloaking) {
        _this._ConnectivityManager.getMobileDataEnabled.overload().implementation = function() {
            Logger.log(_this.LOG_TYPE, _this.NAME, `ConnectivityManager.getMobileDataEnabled: true`)
            return true
      };
    }
}
