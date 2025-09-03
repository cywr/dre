import { Logger } from "../utils/logger";

export abstract class Hook {
    abstract readonly NAME: string;
    abstract readonly LOG_TYPE: Logger.Type;

    protected log = (message: string) => {
        Logger.log(this.LOG_TYPE, this.NAME, message);
    }

    abstract info(): void;
    abstract execute(): void;
}