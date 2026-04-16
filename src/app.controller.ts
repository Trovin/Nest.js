import {Controller, Get} from "@nestjs/common";
import * as process from "node:process";

@Controller('')
export class AppController {
    @Get()
    log() {
        return {
            message: `Nest is running on ${process.env.PORT}`
        }
    }
}