'use strict';
const uuid = require('uuid');
const AWS = require('aws-sdk'); 
const dynamoDb = new AWS.DynamoDB.DocumentClient();
const iot = new AWS.Iot();
const awsIoTBaseArn = 'arn:aws:iot:ap-southeast-1:124891600745';
const CognitoExpress = require("cognito-express");
const cognitoUserPoolId = "ap-southeast-1_iZlJFT6k8";
const cognitoIdentityServiceProvider = new AWS.CognitoIdentityServiceProvider();
const cognitoExpress = new CognitoExpress({
  region: "ap-southeast-1",
  cognitoUserPoolId: cognitoUserPoolId,
  tokenUse: "access", //Possible Values: access | id
  tokenExpiration: 3600000 //Up to default expiration of 1 hour (3600000 ms)
});

function createIoTPolicy(gateway, user) {
  const policyDocument = {
    Version: '2012-10-17',
    Statement: [{
      Effect: 'Allow',
      Action: 'iot:Connect',
      Resource: '*'
    },
      {
        Effect: 'Allow',
        Action: [
          'iot:Subscribe'
        ],
        Resource: [
          `${awsIoTBaseArn}:topicfilter/vitysmarthome/${gateway}/${user}/*`
        ]
      },
      {
        Effect: 'Allow',
        Action: [
          'iot:*'
        ],
        Resource: [
          `${awsIoTBaseArn}:topic/vitysmarthome/${gateway}/${user}/*`
        ]
      },
      {
        Effect: 'Allow',
        Action: [
          'iot:Subscribe'
        ],
        Resource: [
          `${awsIoTBaseArn}:topicfilter/vitysmarthome/${gateway}/broadcast`
        ]
      },
    ]
  };
  const params = {
    policyDocument: JSON.stringify(policyDocument),
    policyName: `VitySmartHomePolicy_${gateway}_${user}`
  };
  let promise = new Promise(resolve => {
    iot.createPolicy(params, (err) => {
      resolve(err);
    })
  })
  return promise;
}

function deleteIoTPolicy(gateway, user) {
  const params = {
    policyName: `VitySmartHomePolicy_${gateway}_${user}`
  };
  let promise = new Promise(resolve => {
    iot.deletePolicy(params, (err) => {
      resolve(err);
    })
  })
  return promise;
}

function attachPrincipalPolicy(gateway, user, principal) {
  const params = {
    policyName: `VitySmartHomePolicy_${gateway}_${user}`,
    principal: principal
  };
  let promise = new Promise(resolve => {
    iot.attachPrincipalPolicy(params, (err) => {
      resolve(err);
    })
  })
  return promise;
}

function validateToken(event, context) {
  let promise = new Promise((resolve, reject) => {
    if (!event.headers.Authorization) {
      const res = {
        statusCode: 403,
        headers: {
          'Access-Control-Allow-Origin': '*', // Required for CORS support to work
        },
        body: JSON.stringify({error: 'Authorization not found'}),
      };
      reject(res);
    }
    let token = event.headers.Authorization.replace('Bearer ', '');
    cognitoExpress.validate(token, (err, response) => {
      if (err) {
        const res = {
          statusCode: 403,
          headers: {
            'Access-Control-Allow-Origin': '*', // Required for CORS support to work
          },
          body: JSON.stringify({error: err}),
        };
        reject(res);
      } else {
        resolve(response);
      }
    })
  });
  return promise;
}

function validateUser(username) {
  var params = {
    UserPoolId: cognitoUserPoolId,
    Username: username
  };
  let promise = new Promise((resolve, reject) => {
    cognitoIdentityServiceProvider.adminGetUser(params, function(err, data) {
      if (err) {
        const res = {
          statusCode: 403,
          headers: {
            'Access-Control-Allow-Origin': '*', // Required for CORS support to work
          },
          body: JSON.stringify({error: 'Authorization not found'}),
        };
        reject(res);
      } else {
        resolve(data);
      }
    });
  });
  return promise;
}

module.exports.attachPrincipalPolicy = (event, context) => {
  const data = JSON.parse(event.body);
  attachPrincipalPolicy(data.gateway, data.user, data.principal)
    .then(err => {
      const response = {
        statusCode: 200,
        headers: {
            'Access-Control-Allow-Origin': '*', // Required for CORS support to work
        },
        body: JSON.stringify({status: 'OK', err}),
      };
      context.done(null, response);
    })
};

module.exports.userAddGateway = (event, context) => {
  validateToken(event, context)
    .then(() => {
      const timestamp = new Date().getTime();
      const data = JSON.parse(event.body);
      validateUser(data.username)
      .then(() => {
        const params = {
          TableName: process.env.DYNAMODB_TABLE_USER_GATEWAY,
          Item: {
            id: uuid.v1(),
            username: data.username,
            gateway: data.gateway,
            permission: data.permission,
            createdUser: data.created_user,
            createdAt: timestamp,
            updatedAt: timestamp,
          },
        };
  
        dynamoDb.put(params, (error) => {
          if (error) {
            console.error(error);
            context.done(null, {
              statusCode: error.statusCode || 501,
              headers: { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*',},
              body: JSON.stringify(error) + JSON.stringify(data),
            })
            return;
          }
  
          const response = {
              statusCode: 200,
              headers: {
                  'Access-Control-Allow-Origin': '*', // Required for CORS support to work
              },
              body: JSON.stringify(params.Item),
            };
          createIoTPolicy(data.gateway, data.username)
            .then(() => {
              context.done(null, response);
            })
        });
      })
      .catch((res) => {
        context.done(null, res);
      })
    })
    .catch(res => {
      context.done(null, res);
    });
};

module.exports.updateUserGateway = (event, context) => {
  validateToken(event, context)
    .then(tokenInfo => {
      const timestamp = new Date().getTime();
      const data = JSON.parse(event.body);
      const params = {
        TableName: process.env.DYNAMODB_TABLE_USER_GATEWAY,
        Key: {
          id: event.pathParameters.id
        },
        ExpressionAttributeValues: {
          // ':username': data.username,
          // ':gateway': data.gateway,
          ':permission': data.permission,
          ':updatedAt': timestamp,
        },
        ExpressionAttributeNames:{
          "#perm": "permission"
        },
        // UpdateExpression: 'SET username = :username, gateway = :gateway, #perm = :permission, updatedAt =:updatedAt',
        UpdateExpression: 'SET #perm = :permission, updatedAt =:updatedAt',
        ReturnValues: 'ALL_NEW',
      };

      dynamoDb.update(params, (error) => {
        if (error) {
          console.error(error);
          context.done(null, {
            statusCode: error.statusCode || 501,
            headers: { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*',},
            body: JSON.stringify({error, data}),
          })
          return;
        }

        const response = {
            statusCode: 200,
            headers: {
                'Access-Control-Allow-Origin': '*', // Required for CORS support to work
            },
            body: JSON.stringify(error) + JSON.stringify(data),
          };
          context.done(null, response);
      });
    })
    .catch(res => {
      context.done(null, res);
    })
}

module.exports.deleteUserGateway = (event, context) => {
  validateToken(event, context)
  .then(() => {
    const params = {
      TableName: process.env.DYNAMODB_TABLE_USER_GATEWAY,
      Key: {
        id: event.pathParameters.id
      },
    };
    
    dynamoDb.get(params, (err, result) => {
      if (!err) {
        deleteIoTPolicy(result.Item.gateway, result.Item.username)
        .then((errpolicy) => {
          dynamoDb.delete(params, (error) => {
            // handle potential errors
            if (error) {
              console.error(error);
              context.done(null, {
                statusCode: error.statusCode || 501,
                headers: { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*',},
                body: JSON.stringify(error),
              })
              return;
            }
        
            // create a response
            const response = {
                statusCode: 200,
                headers: {
                    'Access-Control-Allow-Origin': '*', // Required for CORS support to work
                },
                body: JSON.stringify({status: 'OK', item: result, err: errpolicy}),
              };
            context.done(null, response);
          });
        })
      }
    })
  })
  .catch(res => {
    context.done(null, res);
  });
    
}

module.exports.userListGateways = (event, context) => {
  validateToken(event, context)
  .then((tokenInfo) => {
    const data = JSON.parse(event.body);
    const params = {
      TableName: process.env.DYNAMODB_TABLE_USER_GATEWAY,
      FilterExpression: "username = :username",
      ExpressionAttributeValues: {
        ":username": data.username
      }, 
    };
    dynamoDb.scan(params, (error, result) => {
      if (error) {
        console.error(error);
        callback(null, {
          statusCode: error.statusCode || 501,
          headers: { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*',},
          body: JSON.stringify(error),
        });
        return;
      }

      const response = {
        statusCode: 200,
        headers: {
          'Access-Control-Allow-Origin': '*', // Required for CORS support to work
        },
        body: JSON.stringify(result),
      };
      context.done(null, response);
    });
      // const response = {
      //     statusCode: 200,
      //     headers: {
      //       'Access-Control-Allow-Origin': '*', // Required for CORS support to work
      //     },
      //     body: JSON.stringify(tokenInfo),
      //   };
      //   context.done(null, response);
  })
  .catch(res => {
    context.done(null, res);
  })
}

module.exports.gatewayGetUsers = (event, context) => {
  validateToken(event, context)
  .then(() => {
    const data = JSON.parse(event.body);
    const params = {
      TableName: process.env.DYNAMODB_TABLE_USER_GATEWAY,
      FilterExpression: "gateway = :gateway",
      ExpressionAttributeValues: {
        ":gateway": data.gateway
      }, 
    };
    dynamoDb.scan(params, (error, result) => {
      if (error) {
        console.error(error);
        callback(null, {
          statusCode: error.statusCode || 501,
          headers: { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*',},
          body: JSON.stringify(error),
        });
        return;
      }

      const response = {
        statusCode: 200,
        headers: {
          'Access-Control-Allow-Origin': '*', // Required for CORS support to work
        },
        body: JSON.stringify(result),
      };
      context.done(null, response);
    });
  })
  .catch(res => {
    context.done(null, res);
  })
}

module.exports.testAccessToken = (event, context) => {
  validateToken(event, context)
    .then(tokenInfo => {
      const response = {
        statusCode: 200,
        headers: {
          'Access-Control-Allow-Origin': '*', // Required for CORS support to work
        },
        body: JSON.stringify(tokenInfo),
      };
      context.done(null, response);
    })
    .catch(res => {
      context.done(null, res);
    })
}