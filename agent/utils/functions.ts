import Java from "frida-java-bridge";

export var bin2ascii = function (input: any) {
    try {
        var buffer = Java.array('byte', input);
        var result = "";

        for (var i = 0; i < buffer.length; ++i) {
            if (buffer[i] > 31 && buffer[i] < 127)
                result += (String.fromCharCode(buffer[i]));
            else result += ' ';
        }
        return result;    
    } catch (error) {
        return `(ERROR) - It wasn't possible to transform ${input} into String.`
    }
}

export var bin2hex = function (bytes: number[]) {
    try {
        return Array.from(bytes, function (byte: number) {
            return ('0' + (byte & 0xFF).toString(16)).slice(-2);
        }).join(' ')
    } catch (error) {
        return `(ERROR) - It wasn't possible to transform ${bytes} into String.`
    }
}