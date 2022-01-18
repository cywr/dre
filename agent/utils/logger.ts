import { debug } from "../";

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
        Error,
        None,
    }

    export function log(type:Type=Type.None, title:string="", text:string) {
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
                if (debug) console.log(Color.Yellow+"[?]"+title+"\x1b[0m "+text);
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
