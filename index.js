const oidc = require('oidc');
const policy = require('awsPolicy');
const authz = require('p1Authz');

exports.handler = async(event, context) => {
    //console.log(JSON.stringify(event));
    //console.log(JSON.stringify(context));
    let iamPolicy = policy.defaultDenyAllPolicy;
    
    const bearerToken = event.headers?.Authorization?.replace("Bearer ", "");
    //console.log('JWT Token', bearerToken);
    
    const access_token = await oidc.validateToken(bearerToken)
    const payload = await authz.buildSidebandBody({event, access_token});
    const decision = await authz.decisionRequest({payload});
    
    iamPolicy =  policy.decisionResponseToPolicy({event, decision, access_token});
    
    console.log('IAM Policy', JSON.stringify(iamPolicy));
    return iamPolicy;
};