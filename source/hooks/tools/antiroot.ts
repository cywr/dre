import Java from "frida-java-bridge"
import { log, LogType } from "../../utils/logger"

/**
 * Anti-Root Detection Bypass
 * Bypasses root/su detection checks across package manager, filesystem, process, and system APIs.
 */
export namespace AntiRoot {
  const NAME = "[AntiRoot]"

  export function info(): void {
    log(
      LogType.Debug,
      NAME,
      `LogType: Hook` +
        `\n╓─┬\x1b[31m Anti-Root Detection Bypass \x1b[0m` +
        `\n║ ├── Package checks: ApplicationPackageManager` +
        `\n║ ├── File system: File, BufferedReader` +
        `\n║ ├── Process: Runtime, ProcessBuilder` +
        `\n║ └── System: SystemProperties, String` +
        `\n╙────────────────────────────────────────────┘`,
    )
  }

  export function perform(): void {
    info()
    try {
      hookApplicationPackageManager()
      hookFile()
      hookRuntime()
      hookProcessBuilder()
      hookSystemProperties()
      hookString()
      hookBufferedReader()
    } catch (error) {
      log(LogType.Error, NAME, `Hooks failed: \n${error}`)
    }
  }

  // ─── ApplicationPackageManager ────────────────────────────────────────

  const ROOTING_PACKAGES = [
    "com.noshufou.android.su",
    "com.noshufou.android.su.elite",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.thirdparty.superuser",
    "com.yellowes.su",
    "com.koushikdutta.rommanager",
    "com.koushikdutta.rommanager.license",
    "com.dimonvideo.luckypatcher",
    "com.chelpus.lackypatch",
    "com.ramdroid.appquarantine",
    "com.ramdroid.appquarantinepro",
    "com.devadvance.rootcloak",
    "com.devadvance.rootcloakplus",
    "de.robv.android.xposed.installer",
    "com.saurik.substrate",
    "com.zachspong.temprootremovejb",
    "com.amphoras.hidemyroot",
    "com.amphoras.hidemyrootadfree",
    "com.formyhm.hiderootPremium",
    "com.formyhm.hideroot",
    "me.phh.superuser",
    "eu.chainfire.supersu.pro",
    "com.kingouser.com",
  ]

  function hookApplicationPackageManager(): void {
    try {
      const PackageManager = Java.use("android.app.ApplicationPackageManager")
      const NameNotFoundException = Java.use(
        "android.content.pm.PackageManager$NameNotFoundException",
      )

      PackageManager.getPackageInfo.overload("java.lang.String", "int").implementation = function (
        packageName: string,
        flags: number,
      ) {
        if (ROOTING_PACKAGES.includes(packageName)) {
          log(LogType.Info, NAME, `PM.getPackageInfo: hiding ${packageName}`)
          throw NameNotFoundException.$new(packageName)
        }

        return this.getPackageInfo.call(this, packageName, flags)
      }
    } catch (error) {
      log(LogType.Error, NAME, `PackageManager hook failed: ${error}`)
    }
  }

  // ─── File ─────────────────────────────────────────────────────────────

  const ROOT_BINARIES = [
    "su",
    "busybox",
    "supersu",
    "Superuser.apk",
    "KingoUser.apk",
    "SuperSu.apk",
  ]

  const FILE_SYSTEM: Record<string, { exists?: boolean; read?: boolean; write?: boolean }> = {
    "/": {
      write: false,
    },
    "/data": {
      write: false,
      read: false,
    },
    "/data/local/bin/su": {
      exists: false,
    },
    "/data/local/su": {
      exists: false,
    },
    "/data/local/xbin/su": {
      exists: false,
    },
    "/dev": {
      write: false,
    },
    "/etc": {
      write: false,
    },
    "/proc": {
      write: false,
    },
    "/sbin": {
      write: false,
    },
    "/sbin/su": {
      exists: false,
    },
    "/sys": {
      write: false,
    },
    "/system/bin/failsafe/su": {
      exists: false,
    },
    "/system/bin/su": {
      exists: false,
    },
    "/system/sd/xbin/su": {
      exists: false,
    },
    "/system/xbin/su": {
      exists: false,
    },
    "/etc/security/otacerts.zip": {
      exists: true,
    },
  }

  function hookFile(): void {
    try {
      hookFileAntiRoot()
      hookFileMonitor()
    } catch (error) {
      log(LogType.Error, NAME, `File hook failed: ${error}`)
    }
  }

  function hookFileAntiRoot(): void {
    try {
      const File = Java.use("java.io.File")

      File.exists.implementation = function () {
        const name = this.getName()
        const override = FILE_SYSTEM[name]

        if (ROOT_BINARIES.includes(name)) {
          log(LogType.Info, NAME, `File.exists: ${name} -> false`)
          return false
        } else if (override && override.exists !== undefined) {
          log(LogType.Info, NAME, `File.exists: ${name} -> ${override.exists}`)
          return override.exists
        } else {
          return this.exists.call(this)
        }
      }

      File.canWrite.implementation = function () {
        const name = this.getName()
        const override = FILE_SYSTEM[name]

        if (override && override.write !== undefined) {
          log(LogType.Info, NAME, `File.canWrite: ${name} -> ${override.write}`)
          return override.write
        } else {
          return this.canWrite.call(this)
        }
      }

      File.canRead.implementation = function () {
        const name = this.getName()
        const override = FILE_SYSTEM[name]

        if (override && override.read !== undefined) {
          log(LogType.Info, NAME, `File.canRead: ${name} -> ${override.read}`)
          return override.read
        } else {
          return this.canRead.call(this)
        }
      }
    } catch (error) {
      log(LogType.Error, NAME, `File antiRoot hook failed: ${error}`)
    }
  }

  function hookFileMonitor(): void {
    try {
      const File = Java.use("java.io.File")
      const FileInputStream = Java.use("java.io.FileInputStream")

      File.$init.overloads.forEach((overload) => {
        overload.implementation = function (...args: any[]) {
          log(LogType.Debug, NAME, `New file: ${args}`)
          return overload.call(this, ...args)
        }
      })

      try {
        const fileInputStreamConstr = FileInputStream.$init.overload("java.io.File")
        fileInputStreamConstr.implementation = function (a0: any) {
          try {
            const file = Java.cast(a0, File)
            const path = file.getAbsolutePath()
            log(LogType.Debug, NAME, `New FileInputStream: ${path}`)
          } catch (error) {
            log(LogType.Debug, NAME, `New FileInputStream (couldn't read filepath)`)
          }
          return fileInputStreamConstr.call(this, a0)
        }
      } catch (error) {
        log(LogType.Error, NAME, `FileInputStream hook failed: ${error}`)
      }
    } catch (error) {
      log(LogType.Error, NAME, `File monitor hook failed: ${error}`)
    }
  }

  // ─── Runtime ──────────────────────────────────────────────────────────

  function hookRuntime(): void {
    try {
      const Runtime = Java.use("java.lang.Runtime")

      Runtime.exec.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          if (typeof args[0] === "string" || args[0] instanceof String) {
            var cmd = args[0].toString()

            if (
              cmd.indexOf("getprop") != -1 ||
              cmd == "mount" ||
              cmd.indexOf("build.prop") != -1 ||
              cmd == "id" ||
              cmd == "sh"
            ) {
              log(LogType.Info, NAME, `Runtime.exec: ${cmd}`)
              return this.exec.call(this, "grep")
            }
            if (cmd == "su") {
              log(LogType.Info, NAME, `Runtime.exec: ${cmd}`)
              return this.exec.call(this, "loremipsum")
            }

            return this.exec.call(this, ...args)
          } else {
            var array = args[0]

            for (var i = 0; i < array.length; i = i + 1) {
              var tmp_cmd = array[i]

              if (
                tmp_cmd.indexOf("getprop") != -1 ||
                tmp_cmd == "mount" ||
                tmp_cmd.indexOf("build.prop") != -1 ||
                tmp_cmd == "id" ||
                tmp_cmd == "sh"
              ) {
                log(LogType.Info, NAME, `Runtime.exec: ${array}`)
                return this.exec.call(this, "grep")
              }
              if (tmp_cmd == "su") {
                log(LogType.Info, NAME, `Runtime.exec: ${array}`)
                return this.exec.call(this, "loremipsum")
              }
            }

            return this.exec.call(this, ...args)
          }
        }
      })
    } catch (error) {
      log(LogType.Error, NAME, `Runtime hook failed: ${error}`)
    }
  }

  // ─── ProcessBuilder ───────────────────────────────────────────────────

  function hookProcessBuilder(): void {
    try {
      const ProcessBuilder = Java.use("java.lang.ProcessBuilder")

      ProcessBuilder.start.implementation = function () {
        var cmd = this.command.call(this)
        var shouldModifyCommand = false

        for (var i = 0; i < cmd.size(); i = i + 1) {
          var tmp_cmd = cmd.get(i).toString()

          if (
            tmp_cmd.indexOf("getprop") != -1 ||
            tmp_cmd.indexOf("mount") != -1 ||
            tmp_cmd.indexOf("build.prop") != -1 ||
            tmp_cmd.indexOf("id") != -1
          ) {
            shouldModifyCommand = true
          }
        }
        if (shouldModifyCommand) {
          log(LogType.Info, NAME, `ProcessBuilder.start: ${cmd}`)
          this.command.call(this, ["grep"])
          return this.start.call(this)
        }
        if (cmd.indexOf("su") != -1) {
          log(LogType.Info, NAME, `ProcessBuilder.start: ${cmd}`)
          this.command.call(this, ["loremipsum"])
          return this.start.call(this)
        }

        return this.start.call(this)
      }
    } catch (error) {
      log(LogType.Error, NAME, `ProcessBuilder hook failed: ${error}`)
    }
  }

  // ─── SystemProperties ─────────────────────────────────────────────────

  function hookSystemProperties(): void {
    try {
      const SystemProperties = Java.use("android.os.SystemProperties")

      SystemProperties.get.overload("java.lang.String").implementation = function (name: string) {
        switch (name) {
          case "ro.build.selinux":
            log(LogType.Info, NAME, `SystemProperties.get: ${name} -> 1`)
            return "1"
          case "ro.debuggable":
            log(LogType.Info, NAME, `SystemProperties.get: ${name} -> 0`)
            return "0"
          case "service.adb.root":
            log(LogType.Info, NAME, `SystemProperties.get: ${name} -> 0`)
            return "0"
          case "ro.secure":
            log(LogType.Info, NAME, `SystemProperties.get: ${name} -> 1`)
            return "1"
          default:
            return this.get.call(this, name)
        }
      }
    } catch (error) {
      log(LogType.Error, NAME, `SystemProperties hook failed: ${error}`)
    }
  }

  // ─── String ───────────────────────────────────────────────────────────

  function hookString(): void {
    try {
      const String = Java.use("java.lang.String")

      String.contains.implementation = function (name: string) {
        switch (name) {
          case "test-keys":
            log(LogType.Debug, NAME, `String.contains: ${name} -> false`)
            return false
          default:
            return this.contains.call(this, name)
        }
      }
    } catch (error) {
      log(LogType.Error, NAME, `String hook failed: ${error}`)
    }
  }

  // ─── BufferedReader ───────────────────────────────────────────────────

  function hookBufferedReader(): void {
    try {
      const BufferedReader = Java.use("java.io.BufferedReader")

      BufferedReader.readLine.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          var text = this.readLine.call(this, ...args)

          if (text !== null && text.indexOf("ro.build.tags=test-keys") > -1) {
            log(
              LogType.Debug,
              NAME,
              `BufferedReader.readLine: ${text} -> ro.build.tags=release-keys`,
            )
            text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys")
          }

          return text
        }
      })
    } catch (error) {
      log(LogType.Error, NAME, `BufferedReader hook failed: ${error}`)
    }
  }
}
