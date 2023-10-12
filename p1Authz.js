const https = require("https");

const oidc = require('oidc');

const config = {};
config.service_url_base = process.env.P1_AUTHZ_SERVICE_HOST;
config.envId = process.env.P1_ENV_ID;
config.shared_secret = process.env.SHARED_SECRET;

const convertRequestHeaders = (requestHeaders) => {
    const result = [];
    for (const [key, value] of Object.entries(requestHeaders)) {
      const pair = {};
      pair[key] = value;
      result.push(pair)
    }
    //return result;
    return [{Authorization: requestHeaders.Authorization}];
}

const buildSidebandBody = async ({event:{resource, httpMethod, headers, queryStringParameters, requestContext: { protocol, identity: { requestContext }, domainName, path }}, access_token}) => {
    const source_ip = headers["X-Forwarded-For"] || requestContext;
    const source_port  = headers["X-Forwarded-Port"] || 443;
    const scheme = headers["X-Forwarded-Proto"] || 'https'
    const url_base = headers.host || domainName;
    const url = `${scheme}://${url_base}${path}`;
    const sbBody = {
        method: httpMethod,
        http_version: protocol.split('/')[1],
        source_ip,
        source_port,
        url,
        headers: convertRequestHeaders(headers),
    }
    if (access_token) sbBody.access_token = access_token;
    
    return sbBody;
}

const decisionRequest = ({payload}) => {
    console.log("About to send", JSON.stringify(payload))
    const postBody = Buffer.from(JSON.stringify(payload));
    
    const options = {
        hostname: config.service_url_base,
        path: `/v1/environments/${config.envId}/sideband/request`,
        method: 'POST',
        headers: {
            'Content-Length': postBody.length,
        }
    };
    options.headers['CLIENT-TOKEN'] = config.shared_secret;
    
    return new Promise((resolve, reject) => {
        const req = https.request(options, resp => {
            let body = '';
            resp.on("data", (chunk) => {
                body += chunk;
            });
            
            resp.on('end', () => {
                //console.log("response object", resp)
                if (resp.statusCode === 200) {
                    console.log("Decision response: ", body);
                    resolve(JSON.parse(body));
               } else {
                    console.log("HTTP Call failed. Error: ", resp.statusCode, resp.statusMessage);
                    reject(JSON.stringify({statusCode: resp.statusCode, statusMessage: resp.statusMessage }));
               }
            });
            
            resp.on('error', (err) => {
                console.log("HTTP Call failed. Error: ", err.message);
                reject(err);
            });
        });
        req.write(postBody);
        req.end();
    });
}

module.exports = {
    buildSidebandBody,
    decisionRequest
}
