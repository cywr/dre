import * as Utils from "../utils/functions"
import { Logger } from "../utils/logger";
import { Hook } from "../interfaces/hook";
import Java from "frida-java-bridge";

/**
 * Perform hooks on the system to bypass anti-debug validations.
*/
export class Scratchpad extends Hook {
    NAME = "[Scratchpad]";
    LOG_TYPE = Logger.Type.Hook;

    info(): void {
        Logger.log(
            Logger.Type.Config, 
            this.NAME, `LogType: Hook`
            + `\n╓─┬\x1b[31m Java Classes \x1b[0m`
            + `\n║ └──\x1b[35m ? \x1b[0m`
            + `\n╟─┬\x1b[31m Native Files \x1b[0m`
            + `\n║ └──\x1b[35m ? \x1b[0m`
            + `\n╙────────────────────────────────────────────────────┘`
        );
    }

    execute(): void {
        this.info()
        try {
            this.startActivity();
            this.testing();
        } catch(error) {
            Logger.log(Logger.Type.Error, this.NAME, `Hooks failed: \n${error}`);
        }
    }

    testing() {
        
    }

    startActivity() {
        const log = this.log;
        const Activity = Java.use("android.app.Activity")

        Activity.startActivity.overloads.forEach((overload:any) => {
            overload.implementation = function (...args: any) {
                log(`Activity.startActivity: ${args}`)
                return this.startActivity(...args);
            }
        });
    }

    traceClass(targetClass:string) {
        var hook;
        try {
            hook = Java.use(targetClass);
        } catch (e) {
            console.error("trace class failed", e);
            return;
        }
      
        var methods = hook.class.getDeclaredMethods();
        hook.$dispose();
      
        var parsedMethods: any[] = [];
        methods.forEach(function (method:any) {
            var methodStr = method.toString();
            var methodReplace = methodStr.replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1];
             parsedMethods.push(methodReplace);
        });
      
        this.uniqBy(parsedMethods, JSON.stringify).forEach((targetMethod:any) => {
            this.traceMethod(targetClass + '.' + targetMethod);
        });
      }
      
      traceMethod(targetClassMethod:any) {
          var delim = targetClassMethod.lastIndexOf(".");
          if (delim === -1) return;
      
          var targetClass = targetClassMethod.slice(0, delim)
          var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length)
      
          var hook = Java.use(targetClass);
          var overloadCount = hook[targetMethod].overloads.length;
      
          console.log("Tracing " + targetClassMethod + " [" + overloadCount + " overload(s)]");
      
          for (var i = 0; i < overloadCount; i++) {
      
              hook[targetMethod].overloads[i].implementation = function() {
                console.log("\n[+] Entering: " + targetClassMethod);
      
                  if (arguments.length) console.log();
                  for (var j = 0; j < arguments.length; j++) {
                      console.log("\targ[" + j + "]: " + arguments[j]);
                  }
      
                  // print retval
                  var retval = this[targetMethod].apply(this, arguments); // rare crash (Frida bug?)
                  console.log("\tRetval: " + retval);
                  console.log("[-] Exiting " + targetClassMethod);
                  return retval;
              }
          }
      }
      
      // remove duplicates from array
      uniqBy(array:any, key:any) {
        var seen: any[] = [];
        return array.filter(function (item:any) {
            var k = key(item);
            return seen.hasOwnProperty(k) ? false : (seen[k] = true);
        });
      }
    
}