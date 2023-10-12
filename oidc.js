const https = require("https");
const crypto = require("crypto");

const config = {};
// The regional host e.g. auth.pingone.com, auth.pingone.eu
config.authPath = process.env.P1_AUTH_HOST || 'auth.pingone.com';
// The environment ID from your PingOne environment
config.envId = process.env.P1_ENV_ID;
// The string or URI identifying this principal
config.audience = process.env.PRINCIPAL;
// The resource ID or worker app client ID associated with the access token
config.client_id = process.env.P1_RESOURCE_ID || process.env.P1_CLIENT_ID;
// The issuer of the access token
config.issuer = process.env.P1_ISSUER || `https://${config.authPath}/${config.envId}/as`;
// this should be handled with a secrets manager; example below
config.client_secret = process.env.P1_RESOURCE_SECRET || process.env.P1_CLIENT_SECRET;
/***
const AWS = require('aws-sdk');
const secretsClient = new AWS.SecretsManager({ region: process.env.AWS_REGION });
secretsClient.getSecretValue({ SecretID: 'ResourceSecret' }, (err, data) => {
    client_secret = data.SecretString;
});
***/


const introspect = (token) => {
    const clientCreds = Buffer.from(`${config.client_id}:${config.client_secret}`);
    const postBody = Buffer.from(`token=${token}`);
    
    const options = {
        hostname: config.authPath,
        path: `/${config.envId}/as/introspect`,
        method: 'POST',
        headers: {
            'Authorization': `Basic ${clientCreds.toString('base64')}`,
            'Content-Type': "application/x-www-form-urlencoded",
            'Content-Length': postBody.length,
        }
    };
    
    return new Promise((resolve, reject) => {
        const req = https.request(options, resp => {
            let body = '';
            resp.on("data", (chunk) => {
                body += chunk;
            });
            
            resp.on('end', () => {
               if (resp.statusCode === 200) {
                   //console.log("Introspect response: ", body);
                   resolve(JSON.parse(body));
               } else {
                   reject({statusCode: resp.statusCode, });
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
};

const getJwks = () => {
    const jwksUri = `https://${config.authPath}/${config.envId}/as/jwks`;
    return new Promise((resolve, reject) => {
        https.get(jwksUri, resp => {
            console.log("JWKS Status Code", resp.statusCode);
            let body = '';
            resp.on("data", (chunk) => {
                body += chunk;
            });
            
            resp.on('end', () => {
               if (resp.statusCode === 200) {
                   //console.log("JWKS Response: ", body)
                   resolve(JSON.parse(body));
               } else {
                   reject({statusCode: resp.statusCode, });
               }
            });
            
            resp.on('error', (err) => {
                console.log(
                    "HTTP Call to retrieve JWKS failed. Error: ", 
                    err.message
                );
                reject(err);
            });
        });
    });
};

const getPublicKey = (key_id) => {
    return getJwks(config).then(({keys}) => {
        const pubKey = keys.find(
            ({ kid, use }) => (kid === key_id && use === 'sig')
        );
        return crypto.createPublicKey({key: pubKey, format: 'jwk'});
    });
}

const decodeJWT = (token) => {
    const parts = token.split('.');
    let [header, payload] = parts.map((part) => Buffer.from(part, 'base64'));
    header = JSON.parse(header.toString());
    payload = JSON.parse(payload.toString());
    const decoded = { header, payload, signature: parts[2] };
    console.log(decoded);
    return decoded;
}

const verifySignature = (token, { header: { kid }, payload, signature }) => {
    console.log("Verifying signature...");
    const verify = crypto.createVerify("RSA-SHA256");
    verify.update(token.split('.', 2).join('.'));
    
    return getPublicKey(kid).then((signerKey) => {
        return verify.verify(signerKey, signature, 'base64');
    });
}

const verifyIssuer = ({ payload: { iss }}) => {
    console.log("Verify Issuer: ", config.issuer, iss);
    return new Promise ((resolve, reject) => {
        if (iss === config.issuer) {
            resolve(true);
        }
        reject("Invalid issuer");
    })
};

const verifyAudience = (audience, { payload: { aud }}) => {
    console.log("Verify Audience: ", audience, aud);
    return new Promise ((resolve, reject) => {
        if (aud.includes(audience)) {
            resolve(true);
        }
        reject("Invalid audience");
    })
};

const verifyTime = ({ payload: { iat, exp }}) => {
    const now = Math.floor(Date.now() / 1000);
    console.log("Verify time: ", `${iat} < ${now} < ${exp}`);
    return new Promise ((resolve, reject) => {
        if ((iat < now) && (now < exp)) {
            resolve(true);
        }
        reject("Invalid iat or exp");
    })
};

const localValidate = (token) => {
    console.log("Validating token locally");
    const decoded = decodeJWT(token);
    return Promise.all([
        verifySignature(token, decoded), 
        verifyIssuer(decoded), 
        verifyAudience(config.audience, decoded), 
        verifyTime(decoded)
    ]).then(() => decoded.payload,(err) => console.log(err));
}

const remoteValidate = (token) => {
    console.log("Validating token with authorization server");
    return introspect(token).then(({active}) => {
        if (active) {
            const { payload } = decodeJWT(token);
            return payload;
        }
        console.log("ValidateToken: token not active");
        return false;
    })
}

const workerValidate = (token) => {
    console.log("Validating worker token");
    const decoded = decodeJWT(token);
    return Promise.all([
        verifySignature(token, decoded), 
        verifyIssuer(decoded), 
        verifyAudience('https://api.pingone.com',decoded), 
        verifyTime(decoded)
    ]).then(() => decoded.payload,(err) => console.log(err));
}

module.exports = {
    localValidate,
    remoteValidate,
    validateToken: localValidate,
    workerValidate
}