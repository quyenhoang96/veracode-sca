import {runAction} from '../srcclr';
import { Options } from "../options";
import * as dotenv from 'dotenv';
dotenv.config();

const options: Options = {
    updateAdvisor: false,
    minCVSSForIssue: 11,
    url: 'https://www.github.com/dancancro/great-big-example-application',
    github_token: process.env.GITHUB_TOKEN || '',
    createIssues: false,
    path: '.',
    debug:false,
    app_guid: '1234',
    vid: '1234',
    vkey: '1234',
    repo: 'dancancro/great-big-example-application',
    owner: 'dancancro',
}

runAction(options);


