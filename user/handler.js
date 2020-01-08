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
  tokenUse: "id", //Possible Values: access | id
  tokenExpiration: 3600000 //Up to default expiration of 1 hour (3600000 ms)
});
const cognitoExpressVoice = new CognitoExpress({
  region: "ap-southeast-1",
  cognitoUserPoolId: cognitoUserPoolId,
  tokenUse: "access", //Possible Values: access | id
  tokenExpiration: 3600000 //Up to default expiration of 1 hour (3600000 ms)
});

function createIoTPolicy(provider, gateway, user) {
  let thingName = `${provider || 'mht'}-gw-${gateway}`;
  let shadowPrefix = `$aws/things/${thingName}/shadow`;
  const policyDocument = {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Action: 'iot:Connect',
        Resource: '*'
      },
      {
        Effect: 'Allow',
        Action: [
          'iot:Publish',
          'iot:Receive'
        ],
        Resource: [
          `arn:aws:iot:ap-southeast-1:124891600745:topic/${provider || 'mht'}/*`,
          `arn:aws:iot:ap-southeast-1:124891600745:topic/${shadowPrefix}/*`
        ]
      },
      {
        Effect: 'Allow',
        Action: [
          'iot:Subscribe',
        ],
        Resource: [
          `arn:aws:iot:ap-southeast-1:124891600745:topicfilter/${provider || 'mht'}/*`,
          `arn:aws:iot:ap-southeast-1:124891600745:topicfilter/${shadowPrefix}/*`
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

function createThing(thingName) {
  const params = {
    thingName: thingName
  };
  let promise = new Promise(resolve => {
    iot.createThing(params, (err, data) => {
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
  let promise = new Promise(resolve => {
    let params = {
      policyName: `VitySmartHomePolicy_${gateway}_${user}`,
      principal: principal
    };
    // attach cognito user into policy
    iot.attachPrincipalPolicy(params, (err) => {
      resolve(err);
    });
  });
  return promise;
}

function attachCertificatePolicy(gateway, user, certid) {
  let promise = new Promise(resolve => {
    let params = {
      policyName: `VitySmartHomePolicy_${gateway}_${user}`,
      principal: `${awsIoTBaseArn}:cert/${certid}`
    };
    // attach device (HC) into policy
    iot.attachPrincipalPolicy(params, (err) => {
      resolve(err);
    })
  });
  return promise;
}

function validateToken(event, context) {
  let promise = new Promise((resolve, reject) => {
    if (!event.headers.Authorization ||
        (event.headers.Authorization && event.headers.Authorization.indexOf('Bearer') < 0)) {
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

function validateTokenFromVoice(event, context) {
  let promise = new Promise((resolve, reject) => {
    if (!event.headers.Authorization ||
        (event.headers.Authorization && event.headers.Authorization.indexOf('Bearer') < 0)) {
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
    cognitoExpressVoice.validate(token, (err, response) => {
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
    cognitoIdentityServiceProvider.adminGetUser(params, function (err, data) {
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

function gatewayExisted(gateway) {
  const params = {
    TableName: process.env.DYNAMODB_TABLE_USER_GATEWAY,
    FilterExpression: "gateway = :gateway",
    ExpressionAttributeValues: {
      ":gateway": gateway
    },
  };
  let promise = new Promise((resolve, reject) => {
    dynamoDb.scan(params, (error, result) => {
      if (error) {
        reject(error);
      } else {
        if (result.Items && result.Items.length > 0) {
          let output = null;
          for (let i = 0; i < result.Items.length; i++) {
            if (result.Items[i].createdUser === result.Items[i].username) {
              output = result.Items[i];
              break;
            }
          }
          resolve(output);
        } else {
          resolve(null);
        }
      }
    });
  });
  return promise;
}

function updateCertificate(certificateId, newStatus) {
  let promise = new Promise(resolve => {
    let params = {
      certificateId: certificateId,
      newStatus: newStatus /* ACTIVE | INACTIVE | REVOKED | PENDING_TRANSFER | REGISTER_INACTIVE | PENDING_ACTIVATION */
    };
    iot.updateCertificate(params, (err, data) => {
      resolve(err);
    });
  });
  return promise;
}

function attachThingPrincipal(principal, thingName) {
  let promise = new Promise(resolve => {
    let params = {
      principal: `${awsIoTBaseArn}:cert/${principal}`,
      thingName: thingName
    };
    iot.attachThingPrincipal(params, (err, data) => {
      resolve(err);
    });
  });
  return promise;
}

function userAddGatewayVoiceActive(username, gateway, active) {
  let tableName =  process.env.DYNAMODB_TABLE_USER_GATEWAY_VOICE_ACTIVE;
  const filter = {
    TableName: tableName,
    KeyConditionExpression: "#usr = :username",
    ExpressionAttributeNames:{
      "#usr": "username"
    },
    ExpressionAttributeValues: {
      ":username": username
    },
  };
  let promise = new Promise(resolve => {
    let needActive = true;
    dynamoDb.query(filter, (error, result) => {
      if (result && result.Items && result.Items.length > 0) {
        let existed = result.Items[0];
        if (existed.gateway === gateway) {
          needActive = false;
        }
      }
      if (needActive) {
        let item = {
          username: username,
          gateway: gateway,
          state: active,
          updatedAt: new Date().getTime()
        };
        let params = {
          TableName: tableName,
          Item: item
        };
        dynamoDb.put(params, (error) => {
          if (error) {
            console.log(error);
            resolve(false);
          } else {
            resolve(true);
          }
        });
      } else {
        resolve(true);
      }
    });
  })
  return promise;
}

module.exports.attachPrincipalPolicy = (event, context) => {
  let response = {
    statusCode: 200,
    headers: {
      'Access-Control-Allow-Origin': '*', // Required for CORS support to work
    }
  };
  validateToken(event, context)
      .then(() => {
        let data = JSON.parse(event.body);
        attachPrincipalPolicy(data.gateway, data.user, data.principal)
            .then(res => {
              if (!res) {
                response.body = JSON.stringify({status: 'OK', res});
                context.done(null, response);
              } else {
                response.body = JSON.stringify({status: 'FAIL', res});
                context.done(null, response);
              }
            })
      })
      .catch(err => {
        response.body = JSON.stringify({status: 'FAIL', err});
        context.done(null, response);
      })
};

module.exports.attachCertDevicePolicy = (event, context) => {
  let response = {
    statusCode: 200,
    headers: {
      'Access-Control-Allow-Origin': '*', // Required for CORS support to work
    }
  };
  validateToken(event, context)
      .then(() => {
        let data = JSON.parse(event.body);
        updateCertificate(data.certId, 'ACTIVE')
            .then(err => {
              if (err) {
                response.body = JSON.stringify({status: 'FAIL', err});
                context.done(null, response);
              } else {
                // create thing
                let thingName = `${data.provider || 'mht'}-gw-${data.gateway}`;
                createThing(thingName).then(err => {
                  if (err) {
                    response.body = JSON.stringify({status: 'FAIL', err});
                    context.done(null, response);
                  } else {
                    attachThingPrincipal(data.certId, thingName)
                        .then(err => {
                          if (err) {
                            response.body = JSON.stringify({status: 'FAIL', err});
                            context.done(null, response);
                          } else {
                            attachCertificatePolicy(data.gateway, data.user, data.certId)
                                .then(err => {
                                  userAddGatewayVoiceActive(data.user, data.gateway, true)
                                      .then(res => {
                                        if (!res) {
                                          console.log("Voice control setting fail")
                                        }
                                        response.body = JSON.stringify({status: 'OK', err});
                                        context.done(null, response);
                                      })
                                })
                          }
                        })
                  }
                })
              }
            })
      })
      .catch(err => {
        response.body = JSON.stringify({status: 'FAIL', err});
        context.done(null, response);
      })
};

module.exports.userAddGateway = (event, context) => {
  validateToken(event, context)
      .then(() => {
        const timestamp = new Date().getTime();
        const data = JSON.parse(event.body);
        let response = {
          statusCode: 200,
          headers: {
            'Access-Control-Allow-Origin': '*', // Required for CORS support to work
          }
        }

        validateUser(data.username)
            .then(() => {
              gatewayExisted(data.gateway)
                  .then(existItem => {
                    let item = {
                      id: uuid.v1(),
                      username: data.username,
                      gateway: data.gateway,
                      permission: data.permission,
                      createdUser: data.created_user,
                      createdAt: timestamp,
                      updatedAt: timestamp
                    };

                    const params = {
                      TableName: process.env.DYNAMODB_TABLE_USER_GATEWAY,
                      Item: item
                    };

                    if (!existItem ||
                        (existItem && existItem.createdUser === data.created_user && data.permission.role === 'guest')) {
                      dynamoDb.put(params, (error) => {
                        if (error) {
                          console.error(error);
                          context.done(null, {
                            statusCode: error.statusCode || 501,
                            headers: {'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*',},
                            body: JSON.stringify(error)
                          })
                          return;
                        }
                        createIoTPolicy(data.provider, data.gateway, data.username)
                            .then(() => {
                              // root dang ky HC lan dau
                              item.exist = false;
                              response.body = JSON.stringify(item);
                              context.done(null, response);
                            })
                      });
                    } else {
                      existItem.username = item.username;
                      // khach dang ky HC da duoc root khai bao tu truoc
                      if (data.created_user !== existItem.createdUser)
                        existItem.permission.role = "guest";
                      // thong tin HC da ton tai
                      existItem.exist = true;
                      response.body = JSON.stringify(existItem);
                      context.done(null, response);
                    }
                  })
                  .catch(res => context.done(null, res))
            })
            .catch(res => {
              context.done(null, res)
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
            id: data.id
          },
          ExpressionAttributeValues: {
            ':permission': data.permission,
            ':updatedAt': timestamp,
          },
          ExpressionAttributeNames: {
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
              headers: {'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*',},
              body: JSON.stringify(error),
            })
            return;
          }

          const response = {
            statusCode: 200,
            headers: {
              'Access-Control-Allow-Origin': '*', // Required for CORS support to work
            },
            body: JSON.stringify(data),
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
        const data = JSON.parse(event.body);
        const params = {
          TableName: process.env.DYNAMODB_TABLE_USER_GATEWAY,
          Key: {
            id: data.id
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
                        headers: {'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*',},
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
            context.done(null, {
              statusCode: error.statusCode || 501,
              headers: {'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*',},
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
            context.done(null, {
              statusCode: error.statusCode || 501,
              headers: {'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*',},
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

module.exports.gatewayVoiceActivated = (event, context) => {
  let response = {
    statusCode: 200,
    headers: {
      'Access-Control-Allow-Origin': '*'
    }
  }
  validateTokenFromVoice(event, context)
      .then(() => {
        let data = JSON.parse(event.body);
        if (data.state === true) {
          let params = {
            TableName : process.env.DYNAMODB_TABLE_USER_GATEWAY_VOICE_ACTIVE,
            KeyConditionExpression: "#usr = :username",
            ExpressionAttributeNames:{
              "#usr": "username"
            },
            ExpressionAttributeValues: {
              ":username": data.username
            }
          };
          dynamoDb.query(params, (error, result) => {
            let output = null;
            if (error) {
              output = error;
              response.statusCode = error.statusCode || 501
            } else {
              if (result && result.Items && result.Items.length > 0) {
                output = result.Items[0];
              }
            }
            response.body = JSON.stringify(output);
            context.done(null, response);
          });
        } else {
          let deleteItem = {
            TableName : process.env.DYNAMODB_TABLE_USER_GATEWAY_VOICE_ACTIVE,
            Key: {
              username: data.username
            }
          }
          dynamoDb.delete(deleteItem, (error, result) => {
            let output = null;
            if (error) {
              output = error;
              response.statusCode = error.statusCode || 501
            } else {
              output = {};
            }
            response.body = JSON.stringify(output);
            context.done(null, response);
          })
        }
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