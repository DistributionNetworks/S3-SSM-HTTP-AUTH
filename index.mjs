//Replace 'user-path' and 'user-password' with the SSM username and password field names
//Change region from 'us-east-1' to correct region where SSM parameters are kept
'use strict';

import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm"; // ES Modules import



export const handler = async (event, context, callback) => {// Get request and request headers
    
    const request = event.Records[0].cf.request;
    const headers = request.headers;

    
    // Configure authentication
    const client = new SSMClient({region: 'us-east-1'});

    //Grab SSM username and password
    const inputPathUser = {
    Name: "user-path",
    WithDecryption: true
    };
    const inputPathPass = { 
        Name: "password-path",
        WithDecryption: true
    };
    const sendPass = new GetParameterCommand(inputPathPass);
    const sendUser = new GetParameterCommand(inputPathUser);

    const passpath = await client.send(sendPass);
    const userpath = await client.send(sendUser);
    
    // Construct the Basic Auth string
    const authString = 'Basic ' + new Buffer(userpath.Parameter.Value + ':' + passpath.Parameter.Value).toString('base64');
    
    // Require Basic authentication
    if (typeof headers.authorization == 'undefined' || headers.authorization[0].value != authString) {
        const body = 'Unauthorized';
        const response = {
            status: '401',
            statusDescription: 'Unauthorized',
            body: body,
            headers: {
                'www-authenticate': [{key: 'WWW-Authenticate', value:'Basic'}]
            },
        };
        callback(null, response);
    }
    // Continue request processing if authentication passed
    callback(null, request);
};
