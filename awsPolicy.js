const apiPermissions = [
    {
        "resource": "*", // NOTE: Replace with your API Gateway Resource
        "stage": "Dev", // NOTE: Replace with your API Gateway Stage
        "httpVerb": "*", // NOTE: Replcae with the HTTP Verbs you want to allow access your REST Resource
        "condition": {
            "attr": "client_id",
            "val": "aa37aac7-5ae3-47ae-bfd5-fb4de88299ce"
        }
    },
    {
        "resource": "abc",
        "stage": "*",
        "httpVerb": "POST",
        "condition": {
            "attr": "scope",
            "val": "service:abc:create" // NOTE: Replace with the proper OAuth scopes that can access your REST Resource
        }
    },
    {
        "resource": "abc",
        "stage": "*",
        "httpVerb": "GET",
        "condition": {
            "attr": "scope",
            "val": "service:abc:read"
        }
    },
    {
        "resource": "abc",
        "stage": "*",
        "httpVerb": "DELETE",
        "condition": {
            "attr": "scope",
            "val": "service:abc:delete"
        }
    }
];

const defaultDenyAllPolicy = {
    "principalId": "user",
    "policyDocument": {
        "Version": "2012-10-17",
        "Statement": [{
            "Action": "execute-api:Invoke",
            "Effect": "Deny",
            "Resource": "*"
        }]
    }
};

function generatePolicyStatement({ stage, httpVerb, resource, action }) {
    // Generate an IAM policy statement
    const arn = `arn:aws:execute-api:${process.env.AWS_REGION}:${process.env.ACCOUNT_ID}:${process.env.API_ID}`;
    const statement = {
        'Action': 'execute-api:Invoke',
        'Effect': 'Allow',
        'Resource': `${arn}/${stage}/${httpVerb}/${resource}`
    };
    console.log({statement});
    return statement;
}

function generatePolicy(principalId, policyStatements) {
    // Generate a fully formed IAM policy
    const authResponse = {};
    authResponse.principalId = principalId;
    const policyDocument = {};
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = policyStatements;
    authResponse.policyDocument = policyDocument;
    return authResponse;
}

const generateIAMPolicy = (claims) => {
    console.log("Generating IAM Policy from ", claims);
    const policyStatements = Array.from( 
        apiPermissions.filter((p) => {
            console.log("Filtering Permissions");
            const { attr, val } = p.condition;
            console.log(`Checking ${attr} for ${val}`);
            const claimVal = claims[attr];
            console.log("Claims value: ", claimVal);
            return claimVal === val
        }),
        p => generatePolicyStatement(p));
    // Check if no policy statements are generated, if so, create default deny all policy statement
    if (policyStatements.length === 0) {
        return defaultDenyAllPolicy;
    } else {
        const { sub, client_id } = claims;
        const principal = sub || client_id;
        return generatePolicy(principal, policyStatements);
    }
};

const decisionResponseToPolicy = ({event: { methodArn, httpMethod, resource }, decision: { response }, access_token: { sub }}) => {
    let effect = "Allow";
    if (response?.response_code && response?.response_code != 200) effect = "Deny";
    const statement = {
        'Action': 'execute-api:Invoke',
        'Effect': effect,
        'Resource': methodArn
    };
    
    return generatePolicy(sub, statement);
}

module.exports = {
    generateIAMPolicy,
    defaultDenyAllPolicy,
    decisionResponseToPolicy
}