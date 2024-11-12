#!/usr/bin/env node

import * as core from '@actions/core'
import { Options } from "./options";
import {runAction} from './srcclr';

const options: Options = {
    updateAdvisor: true,
    minCVSSForIssue: parseFloat(core.getInput('min-cvss-for-issue')) || 0,
    url: core.getInput('url'),
    github_token: core.getInput('github_token',{required:true}),
    createIssues: true,
    path: core.getInput('path',{trimWhitespace: true}) || '.',
    debug: true,
    app_guid: core.getInput('app_guid',{required:true}),
    vid: core.getInput('vid',{required:true}),
    vkey: core.getInput('vkey',{required:true}),
    repo: core.getInput('repo',{required:true}),
    owner: core.getInput('owner',{required:true}),
}

runAction(options);