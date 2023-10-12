## Description
**_NOT FOR PRODUCTION USE_**

This repo contains the code for an AWS Lambda function to be used as an API Gateway authorizer. The function will validate ('locally' or using PingOne's token introspection endpoint) bearer tokens, make a sideband request to PingOne Authorize, and return an AWS IAM Policy as appropriate. 
## Setup steps:
**_NOT FOR PRODUCTION USE_**

1. [Define your API in PingOne Authorize](https://docs.pingidentity.com/r/en-us/pingone/p1az_add_api_service)
2. Download this repo as a zip file
3. Create a new Lambda function (tested with the 'Author from scratch' option)
4. On the 'Code' tab, click 'Upload from' in the top right of the 'Code source' section and click '.zip file' from the drop-down
5. Click 'Upload' in the modal and choose the repo file from step one, then click 'Save'
6. Click the' Configuration' tab Above the 'Code source' section and select 'Environment variables' from the left-hand blade. Click 'Edit'
7. Add an environment variable for each of the keys in the table below:

| Key                  | Example                                 | Description  |
| -------------------- |:---------------------------------------:| -----|
| `ACCOUNT_ID`         | `446709521779`                          | Your AWS account ID without dashes. Used for constructing the arn value of the policy |
| `API_ID`             | `z2ifzjzoyc`                            | The API ID that this authorizer is protecting. Used for constructing the arn value of the policy
| `P1_AUTH_HOST`       | `auth.pingone.com`                      | The host for the region where your PingOne environment is deployed. Used to construct the JWKS URL and introspection endpoint URL
| `P1_ENV_ID`          | `10e1501e-b379-4788-9bb0-5393953a4713`  | Your PingOne environment ID. Used to construct the JWKS URL and introspection endpoint URL
| `P1_RESOURCE_ID`     | `4d4a8be7-8e52-481a-9d60-29458b912f4d`  | The ID of the resource defined in PingOne. Used to authenticate the request to the introspection endpoint
| `P1_RESOURCE_SECRET` | `aaaaaaaaaa.bbbbbbbbbb.cccccccccccccc`  | The client secret of the resource defined in PingOne. Used to authenticate the request to the introspection endpoint
| `PRINCIPAL`          | `PetStore`                              | The audience of resource defined in PingOne. Used to validate the audience of the access token locally
| `SHARED_SECRET`      | `aaaaaaaaaa.bbbbbbbbbb.cccccccccccccc`  | The credential of your API Gateway instance from PingOne Authorize. Used to authenticate requests from the Lambda function to PingOne Authorize
8. [Complete the authorizer configuration with the Lambda function we just created.](https://docs.aws.amazon.com/apigateway/latest/developerguide/configure-api-gateway-lambda-authorization-with-console.html) Follow the steps for `TOKEN` authorizer type and use the  `Authorization` header for the value
