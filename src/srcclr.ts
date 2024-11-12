import * as core from '@actions/core'
import { Options } from "./options";
import { run } from "./index";


export async function runAction (options: Options)  {
    try {
        console.log("Running action")
        

        run(options,core.info);

        console.log("Finish action")
    } catch (error) {
        if (error instanceof Error) {
            core.info('Running scan failed.')
            //const output = stdout.toString();
            core.info(error.message);
            //core.setFailed(error.message);
        } else {
            core.setFailed("unknown error");
            console.log(error);
        }
    }
}


