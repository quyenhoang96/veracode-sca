import { Options } from './options';
import { Octokit } from '@octokit/core';
import { ReportedLibraryIssue } from './srcclr.d';
import { Label, VERACODE_LABEL } from './labels';
import crypto from 'crypto-js';
import url from 'url';

const computeHashHex = (message: string, key_hex: string) => {
    return crypto.HmacSHA256(message, crypto.enc.Hex.parse(key_hex)).toString(crypto.enc.Hex);
}

const calculateDataSignature = (apikey: any, nonceBytes: string, dateStamp: any, data: any) => {
    const requestVersion = "vcode_request_version_1";

    const kNonce = computeHashHex(nonceBytes, apikey);
    const kDate = computeHashHex(dateStamp, kNonce);
    const kSig = computeHashHex(requestVersion, kDate);

    return computeHashHex(data, kSig);
}

const newNonce = () => {
    const nonceSize = 16;
    return crypto.lib.WordArray.random(nonceSize).toString().toUpperCase();
}

const toHexBinary = (input: string) => {
    return crypto.enc.Hex.stringify(crypto.enc.Utf8.parse(input))
}

const removePrefixFromApiCredential = (input: string) => {
    return input.split('-').at(-1);
}

function calculateVeracodeAuthHeader(httpMethod: string, requestUrl: string, vid: string, vkey: string) {
    const authorizationScheme = 'VERACODE-HMAC-SHA-256';

    const formattedId = removePrefixFromApiCredential(vid);
    const formattedKey = removePrefixFromApiCredential(vkey);

    let parsedUrl = url.parse(requestUrl);
    let data = `id=${formattedId}&host=${parsedUrl.hostname}&url=${parsedUrl.path}&method=${httpMethod}`;
    let dateStamp = Date.now().toString();
    let nonceBytes = newNonce();
    let dataSignature = calculateDataSignature(formattedKey, nonceBytes, dateStamp, data);
    let authorizationParam = `id=${formattedId},ts=${dateStamp},nonce=${toHexBinary(nonceBytes)},sig=${dataSignature}`;

    return authorizationScheme + " " + authorizationParam;
}



// Define finding type
type FindingType = {
    scan_type: string,
    description: string,
    count: number,
    context_type: string,
    context_guid: string,
    violates_policy: boolean,
    finding_status: {
        first_found_date: string,
        status: string,
        resolution: string,
        new: boolean,
        resolution_status: string,
        last_seen_date: string
    },
    finding_details: {
        version: string,
        language: string,
        component_path: Array<{
            path: string
        }>,
        severity: number,
        component_id: string,
        licenses: Array<{
            license_id: string,
            risk_rating: string
        }>,
        metadata: {
            sca_scan_mode: string,
            sca_dep_mode: string
        },
        cve: {
            name: string,
            cvss: number,
            href: string,
            severity: string,
            vector: string,
            cvss3: {
                score: number,
                severity: string,
                vector: string
            },
            exploitability: {
                full_cve: string,
                epss_score: number,
                epss_percentile: number,
                epss_score_date: string,
                epss_model_version: string,
                epss_citation: string,
                epss_status: string,
                exploit_service_status: string
            }
        },
        product_id: string,
        component_filename: string,

    }
}

/* Have five steps
Step 1: Fetch VCEs from Vera
Step 2: Fetch Issues from github
Step 3: Filter issues need to be created and closed
Step 4: Create issues
Step 5: Close issues
*/

// Step 1: Fetch from Vera
const fetchStaticFindings = async (app_guid: string, vid: string, vkey: string) => {
    try {
        const requestUrl = `https://api.veracode.com/appsec/v2/applications/${app_guid}/findings?scan_type=SCA`;

        const hmac = calculateVeracodeAuthHeader("GET", requestUrl, vid, vkey);

        const response = await fetch(requestUrl, {
            method: 'GET',
            headers: {
                'Authorization': hmac
            }
        });

        if (!response.ok) {
            throw new Error(`Network response was not ok: ${response.statusText}`);
        }

        const data = await response.json();

        return data._embedded.findings;
    } catch (error) {
        console.error('Fetch error:', error);
        throw new Error("Error when fetchStaticFindings");
    }
}

// Step 2: Fetch Issues from github
const fetchIssues = async (ower: string, repo: string, github_token: string) => {
    let ises;
    try {
        const octokit = new Octokit({
            auth: github_token
        })
''
        const { data } = await octokit.request(`GET /repos/{owner}/{repo}/issues?labels=Veracode`, {
            owner: ower,
            repo: repo,
            headers: {
                'X-GitHub-Api-Version': '2022-11-28'
            }
        })

        ises = data;

    } catch (error) {
        console.error('Fetch error:', error);
        throw new Error("Error when fetchIssues");
    }

    const issues: Array<{
        node: {
            title: string,
            number: number
        }
    }> = [];

    ises.forEach((issue: any) => {
        issues.push({
            node: {
                title: issue.title,
                number: issue.number
            }
        });
    })


    return issues;
}

const filterIssuesCreate = (scaData: Array<FindingType>, issues: Array<any>) => {
    const issuesCreate = new Array<ReportedLibraryIssue>();

    scaData.forEach((finding) => {
        finding.finding_details.component_path.forEach((componentPath) => {
            const componentPathArray = componentPath.path.split("-");
            const team = componentPathArray[1];
            const service = componentPathArray[2]

            const teamLabel: Label = {
                name: "Team: " + team,
                color: '0AA2DC',
                description: 'Team'
            }
            // // label service
            const serviceLabel: Label = {
                name: "Service: " + service,
                color: 'A90533',
                description: 'Service'
            }

            const severityLabel: Label = {
                name: "Severity: " + finding.finding_details.cve.severity,
                color: 'FF0000',
                description: 'Severity'
            }

            const title = "[" + team + "]" + "[" + service + "]" + "- CVE: " + finding.finding_details.cve.name + " found in " + finding.finding_details.component_filename + " - version: " + finding.finding_details.version;
            const description = "Veracode Software Composition Analysis" +
                "  \n===============================\n" +
                "  \n Attribute | Details" +
                "  \n| --- | --- |" +
                "  \nLibrary | " + finding?.finding_details.version +
                "  \nDescription | " + finding?.description +
                "  \nLanguage | " + finding?.finding_details?.language +
                "  \nVulnerability | " + finding.finding_details.cve.href +
                "  \nCVE | " + finding.finding_details.cve.name +
                "  \nCVSS score | " + finding.finding_details.cve.cvss3.score;


            let found = false;
            issuesCreate.forEach((issue) => {
                if (issue.title === title) {
                    found = true;
                }
            })
            let foundIssue = issues.find((issue) => {
                return issue.node.title === title;
            })

            if (!found && !foundIssue) {
                issuesCreate.push({
                    title: title,
                    description: description,
                    labels: [teamLabel, serviceLabel, severityLabel, VERACODE_LABEL],
                })
            }
        })
    })

    return issuesCreate;
}

const filterIssuesClose = (scaData: Array<FindingType>, issues: Array<any>) => {
    const issuesClose = new Array<any>();

    issues.filter(issue => issue.node.title.includes("- CVE:")).forEach((issue) => {
        let found = false;
        // notfound in scaData by title
        scaData.forEach((finding) => {
            finding.finding_details.component_path.forEach((componentPath) => {
                const componentPathArray = componentPath.path.split("-");
                const team = componentPathArray[1];
                const service = componentPathArray[2]

                const title = "[" + team + "]" + "[" + service + "]" + "- CVE: " + finding.finding_details.cve.name + " found in " + finding.finding_details.component_filename + " - version: " + finding.finding_details.version;
                if (issue.node.title === title) {
                    found = true;
                }
            })
        })


        if (!found) {
            issuesClose.push(issue);
        }
    })


    return issuesClose;
}

// Step 4: Create issues
const createIssues = async (owner: string, issues: Array<ReportedLibraryIssue>, repo: string, github_token: string) => {
    const octokit = new Octokit({
        auth: github_token
    })

    issues.forEach(async (issue) => {
        try {
            await octokit.request('POST /repos/{owner}/{repo}/issues', {
                owner: owner,
                repo: repo,
                title: issue.title,
                body: issue.description,
                labels: issue.labels,
                headers: {
                    'X-GitHub-Api-Version': '2022-11-28'
                }
            })
        } catch (error) {
            console.error('Create issue error:', error);
            throw new Error("Error when createIssues");
        }

    });
}

// Step 5: Close issues
const closeIssues = async (ower: string, issues: Array<any>, repo: string, github_token: string) => {
    const octokit = new Octokit({
        auth: github_token
    })

    issues.forEach(async (issue) => {
        try {
            await octokit.request('PATCH /repos/{owner}/{repo}/issues/{issue_number}', {
                owner: ower,
                repo: repo,
                issue_number: issue.node.number,
                state: 'closed',
                title: issue.node.title,
                headers: {
                    'X-GitHub-Api-Version': '2022-11-28'
                }
            })
        } catch (error) {
            console.error('Close issue error:', error);
            throw new Error("Error when closeIssues");
        }

    });
}

export async function run(options: Options, msgFunc: (msg: string) => void) {
    let scaData: Array<FindingType>
    let issues: Array<any>
    try {
        // Step 1: Fetch from Vera
        scaData = await fetchStaticFindings(options.app_guid, options.vid, options.vkey);
        // Step 2: Fetch Issues from github
        issues = await fetchIssues(options.owner, options.repo, options.github_token);
    } catch (error) {
        msgFunc('Running scan failed.')
        throw new Error("Error when fetching data");
    }
    // Step 3: Filter issues need to be created and closed
    const issuesCreate: Array<ReportedLibraryIssue> = filterIssuesCreate(scaData, issues);
    const issuesClose: Array<any> = filterIssuesClose(scaData, issues);

    // Step 4: Create issues
    await createIssues(options.owner, issuesCreate, options.repo, options.github_token);

    // Sleep 10s before close issues
    await new Promise(resolve => setTimeout(resolve, 10000));
    // Step 5: Close issues
    await closeIssues(options.owner, issuesClose, options.repo, options.github_token);
}


