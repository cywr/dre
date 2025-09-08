export namespace Logger {
    export enum Color {
        Red = "\x1b[31m",
        Yellow = "\x1b[33m",
        Green = "\x1b[32m",
        Blue = "\x1b[34m",
        Cyan = "\x1b[36m",
        Magenta = "\x1b[35m"
    }

    export enum Type {
        Info,
        Config,
        Hook,
        Debug,
        Verbose,
        Error,
        None,
    }

    export enum LogLevel {
        ERROR = 0,
        INFO = 1,
        DEBUG = 2,
        VERBOSE = 3
    }

    let currentLogLevel: LogLevel = LogLevel.INFO;

    export function setLogLevel(level: LogLevel): void {
        currentLogLevel = level;
    }

    export function getLogLevel(): LogLevel {
        return currentLogLevel;
    }

    function shouldLog(type: Type): boolean {
        switch (type) {
            case Type.Error:
                return currentLogLevel >= LogLevel.ERROR;
            case Type.Info:
            case Type.Config:
            case Type.Hook:
                return currentLogLevel >= LogLevel.INFO;
            case Type.Debug:
                return currentLogLevel >= LogLevel.DEBUG;
            case Type.Verbose:
                return currentLogLevel >= LogLevel.VERBOSE;
            case Type.None:
            default:
                return true;
        }
    }

    export function log(type:Type=Type.None, title:string="", text:string) {
        if (!shouldLog(type)) {
            return;
        }

        switch(type){
            case Type.Info:
                console.log(Color.Cyan+"[i]"+title+"\x1b[0m "+text);
                break
            case Type.Config:
                console.log(Color.Blue+"[*]"+title+"\x1b[0m "+text);
                break
            case Type.Hook:
                console.log(Color.Green+"[+]"+title+"\x1b[0m "+text);
                break
            case Type.Debug:
                console.log(Color.Yellow+"[?]"+title+"\x1b[0m "+text);
                break
            case Type.Verbose:
                console.log(Color.Magenta+"[v]"+title+"\x1b[0m "+text);
                break
            case Type.Error:
                console.log(Color.Red+"[!]"+title+"\x1b[0m "+text);
                break
            default:
                console.log("[ ]"+title+" "+text);
                break
        };   
    }
}
