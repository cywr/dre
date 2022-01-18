import { Logger } from "../utils/logger";

export interface Hook {
    readonly NAME: string;
    readonly LOG_TYPE: Logger.Type;

    info(): void;
    execute(): void;
}