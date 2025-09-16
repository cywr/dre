import { Logger } from "./logger";
import Java from "frida-java-bridge";

/**
 * Utility class for detecting and extracting DEX files from byte arrays
 */
export namespace DexExtractor {
    const NAME = "[DexExtractor]";
    const log = (message: string) => Logger.log(Logger.Type.Info, NAME, message);
    
    // DEX file magic bytes: "dex\n" followed by version
    const DEX_MAGIC = [0x64, 0x65, 0x78, 0x0a]; // "dex\n"
    
    /**
     * Checks if the byte array starts with DEX magic bytes
     */
    export function isDexFile(data: any): boolean {
        try {
            const buffer = Java.array('byte', data);
            if (buffer.length < 8) return false; // DEX header is at least 8 bytes
            
            // Check for "dex\n" magic bytes
            for (let i = 0; i < DEX_MAGIC.length; i++) {
                if (buffer[i] !== DEX_MAGIC[i]) {
                    return false;
                }
            }
            
            // Check for version pattern (should be like "035\0" or similar)
            if (buffer.length >= 8) {
                const version = [buffer[4], buffer[5], buffer[6], buffer[7]];
                // Version should be 3 digits followed by null byte
                return (version[0] >= 0x30 && version[0] <= 0x39 && // '0'-'9'
                       version[1] >= 0x30 && version[1] <= 0x39 && // '0'-'9'  
                       version[2] >= 0x30 && version[2] <= 0x39 && // '0'-'9'
                       version[3] === 0x00); // null terminator
            }
            
            return false;
        } catch (error) {
            return false;
        }
    }
    
    /**
     * Extracts DEX file information from the header
     */
    export function getDexInfo(data: any): { version: string, fileSize: number, checksum: number } | null {
        try {
            const buffer = Java.array('byte', data);
            if (!isDexFile(data) || buffer.length < 32) return null;
            
            // Extract version (bytes 4-7, null terminated)
            const version = String.fromCharCode(buffer[4], buffer[5], buffer[6]);
            
            // Extract file size (bytes 32-35, little endian)
            const fileSize = (buffer[32] & 0xFF) | 
                           ((buffer[33] & 0xFF) << 8) | 
                           ((buffer[34] & 0xFF) << 16) | 
                           ((buffer[35] & 0xFF) << 24);
            
            // Extract checksum (bytes 8-11, little endian)  
            const checksum = (buffer[8] & 0xFF) | 
                           ((buffer[9] & 0xFF) << 8) | 
                           ((buffer[10] & 0xFF) << 10) | 
                           ((buffer[11] & 0xFF) << 24);
            
            return { version, fileSize, checksum };
        } catch (error) {
            return null;
        }
    }
    
    /**
     * Saves DEX file to device's public tmp directory
     */
    export function saveDexFile(data: any, context: string, operation: string): boolean {
        try {
            const buffer = Java.array('byte', data);
            const dexInfo = getDexInfo(data);
            
            if (!dexInfo) {
                log("Failed to extract DEX info for saving");
                return false;
            }
            
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `dex_${context}_${operation}_${timestamp}_v${dexInfo.version}.dex`;
            
            // Try multiple possible directories in order of preference
            const possibleDirs = [
                '/sdcard/Download/dre_extractions',
                '/sdcard/Documents/dre_extractions', 
                '/data/local/tmp/dre_extractions',
                '/sdcard/dre_extractions'
            ];
            
            const File = Java.use('java.io.File');
            let devicePath = '';
            let extractionsDir = null;
            
            // Find a writable directory
            for (let dir of possibleDirs) {
                try {
                    extractionsDir = File.$new(dir);
                    if (!extractionsDir.exists()) {
                        extractionsDir.mkdirs();
                    }
                    
                    // Test if we can write to this directory
                    if (extractionsDir.canWrite()) {
                        devicePath = `${dir}/${filename}`;
                        break;
                    }
                } catch (dirError) {
                    // Continue to next directory
                    continue;
                }
            }
            
            if (!devicePath) {
                throw new Error("No writable directory found on device");
            }
            
            // Write file using Java FileOutputStream
            const FileOutputStream = Java.use('java.io.FileOutputStream');
            const fileStream = FileOutputStream.$new(devicePath);
            
            try {
                fileStream.write(buffer);
                fileStream.close();
                
                log(`DEX file saved to device!
 - Path: ${devicePath}
 - Size: ${buffer.length} bytes (expected: ${dexInfo.fileSize})
 - Version: ${dexInfo.version}
 - Checksum: 0x${dexInfo.checksum.toString(16)}
 - Context: ${context} ${operation}
 - Use 'pnpm run pull-dex' to copy files to local _build folder`);
                
                return true;
            } catch (writeError) {
                fileStream.close();
                throw writeError;
            }
            
        } catch (error) {
            log(`Failed to save DEX file to device: ${error}`);
            return false;
        }
    }
    
    /**
     * Processes data and extracts DEX if detected, returns truncated summary for logging
     */
    export function processAndExtract(data: any, context: string, operation: string): { 
        summary: string, 
        isDex: boolean, 
        extracted: boolean 
    } {
        try {
            const buffer = Java.array('byte', data);
            const isDex = isDexFile(data);
            
            if (isDex) {
                const extracted = saveDexFile(data, context, operation);
                const dexInfo = getDexInfo(data);
                
                const summary = `DEX FILE DETECTED (${buffer.length} bytes)
 - Version: ${dexInfo?.version || 'unknown'}
 - Expected size: ${dexInfo?.fileSize || 'unknown'} bytes
 - Checksum: 0x${dexInfo?.checksum?.toString(16) || 'unknown'}
 - ${extracted ? 'Successfully saved to device' : 'Extraction FAILED'}`;
                
                return { summary, isDex: true, extracted };
            } else {
                // For non-DEX data, show truncated preview
                let preview = "";
                const previewSize = Math.min(64, buffer.length);
                
                // Show as hex for first 32 bytes
                for (let i = 0; i < Math.min(32, previewSize); i++) {
                    preview += ('0' + (buffer[i] & 0xFF).toString(16)).slice(-2) + ' ';
                }
                if (buffer.length > 32) preview += '...';
                
                // Add ASCII preview for first 64 bytes
                let ascii = "";
                for (let i = 0; i < previewSize; i++) {
                    const char = buffer[i] & 0xFF;
                    ascii += (char > 31 && char < 127) ? String.fromCharCode(char) : '.';
                }
                if (buffer.length > previewSize) ascii += '...';
                
                const summary = `Data (${buffer.length} bytes)
 - Hex: ${preview}
 - ASCII: ${ascii}`;
                
                return { summary, isDex: false, extracted: false };
            }
        } catch (error) {
            return { 
                summary: `Error processing data: ${error}`, 
                isDex: false, 
                extracted: false 
            };
        }
    }
}