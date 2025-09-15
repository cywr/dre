import { Logger } from "../../utils/logger";

/**
 * Generic native method hooking utility for Frida
 * Provides a flexible interface to hook native library methods with customizable callbacks
 */
export namespace Native {
    const NAME = "[Native]";
    const log = (message: string) => Logger.log(Logger.Type.Hook, NAME, message);

    export interface HookConfig {
        library: string;
        method: string;
        onEnter?: (args: NativePointer[], context: any) => void;
        onLeave?: (retval: NativePointer, context: any) => void;
    }

    /**
     * Hook a native method from a specified library
     * @param config Configuration object containing library, method, and callbacks
     */
    export function attach(config: HookConfig): void {
        try {
            const address = (Module as any).findExportByName(config.library, config.method);
            
            if (!address) {
                Logger.log(Logger.Type.Error, NAME, `Method '${config.method}' not found in library '${config.library}'`);
                return;
            }

            log(`Hooking ${config.library}::${config.method} at ${address}`);

            Interceptor.attach(address, {
                onEnter: function(args) {
                    log(`→ Entering ${config.library}::${config.method}`);
                    
                    if (config.onEnter) {
                        try {
                            config.onEnter(args, this);
                        } catch (error) {
                            Logger.log(Logger.Type.Error, NAME, `onEnter callback error: ${error}`);
                        }
                    }
                },
                onLeave: function(retval) {
                    log(`← Leaving ${config.library}::${config.method} with return value: ${retval}`);
                    
                    if (config.onLeave) {
                        try {
                            config.onLeave(retval, this);
                        } catch (error) {
                            Logger.log(Logger.Type.Error, NAME, `onLeave callback error: ${error}`);
                        }
                    }
                }
            });

        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Failed to hook ${config.library}::${config.method}: ${error}`);
        }
    }

    /**
     * Hook multiple methods at once
     * @param configs Array of hook configurations
     */
    export function attachMany(configs: HookConfig[]): void {
        configs.forEach(config => attach(config));
    }

    /**
     * Helper function to read a C string from a pointer
     * @param ptr Pointer to the string
     * @returns String content or null if invalid
     */
    export function readCString(ptr: NativePointer): string | null {
        try {
            return ptr.readCString();
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Failed to read C string: ${error}`);
            return null;
        }
    }

    /**
     * Helper function to read UTF-8 string from a pointer
     * @param ptr Pointer to the string
     * @param length Optional length parameter
     * @returns String content or null if invalid
     */
    export function readUtf8String(ptr: NativePointer, length?: number): string | null {
        try {
            return length ? ptr.readUtf8String(length) : ptr.readUtf8String();
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Failed to read UTF-8 string: ${error}`);
            return null;
        }
    }

    /**
     * Helper function to dump memory as hex
     * @param ptr Pointer to memory
     * @param size Size in bytes
     * @returns Hex dump string
     */
    export function hexDump(ptr: NativePointer, size: number): string {
        try {
            return hexdump(ptr, { length: size, ansi: false });
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Failed to hex dump: ${error}`);
            return "";
        }
    }

    /**
     * Helper function to get the base address of a module
     * @param moduleName Name of the module
     * @returns Base address or null if not found
     */
    export function getModuleBase(moduleName: string): NativePointer | null {
        try {
            const module = Process.findModuleByName(moduleName);
            return module ? module.base : null;
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Failed to get module base for '${moduleName}': ${error}`);
            return null;
        }
    }

}