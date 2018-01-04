'use strict';

const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const querystring = require('querystring');
const config = require("./config");

const jwtSecret = config.jwtSecret;
const issuer = config.issuer || false;
const couchSecret = config.couchSecret;

if (!jwtSecret || !couchSecret) {
  throw new Error("jwtSecret and couchSecret must be provided in config.js!");
}

function parseCookies(cookiestring) {
  var list = {};
  var rc = cookiestring;

  rc && rc.split(';').forEach(function( cookie ) {
    var parts = cookie.split('=');
    list[parts[0].trim()] = decodeURI(parts.slice(1).join('='));
  });

  return list;
}

const CouchUserNameHeader = "X-Auth-CouchDB-UserName";
const CouchRoleHeader = "X-Auth-CouchDB-Roles";
const CouchTokenHeader = "X-Auth-CouchDB-Token";
const jwtCouchUserNameField = "sub";
const jwtCouchRoleField = "roles";

function getToken(request) {
  const queryStringParameters = querystring.decode(request.querystring || "");
  const headers = request.headers;
  let token;
  if (headers) {
    if (headers.authorization) {
      let bearerHeader = headers.authorization[0].value;
      let splitted = bearerHeader.split(" ");
      if (splitted.length !== 2 || !/^Bearer$/i.test(splitted[0])) {
        return;
      }
      else {
        token = splitted[1];
      }
    }
    else if (headers.cookie) {
      for (let i = 0; i < headers.cookie.length; i++) {
        let parsedCookies = parseCookies(headers.cookie[i].value);
        if (Object.keys(parsedCookies).indexOf("jwt_token") >= 0) {
          token = parsedCookies["jwt_token"];
          break;
        }
      }
    }
  }
  if (request.queryStringParameters["token"]) {
    token = request.queryStringParameters["token"];
    delete request.queryStringParameters.token;
    request.queryString = querystring.encode(request.queryStringParameters);
  }
  if (!token) {
    return null;
  }
  return token;
}

function ValidateToken(token) {
  return new Promise((resolve, reject) => {
    //Fail if the token is not jwt
    var decodedJwt = jwt.decode(token, {complete: true});
    if (!decodedJwt) {
      console.log("Not a valid JWT token");
      reject("Unauthorized");
      return;
    }

    //Fail if token is not from your User Pool
    if (decodedJwt.payload.iss != iss) {
      console.log("invalid issuer");
      reject("Unauthorized");
      return;
    }

    //Reject the jwt if it's not an 'Access Token'
    if (decodedJwt.payload.token_use !== "access") {
      console.log("Not an access token");
      reject("Unauthorized");
      return;
    }

    try {
      const payload = jwt.verify(token, config.jwtSecret, { issuer: iss });
    }
    catch(err) {
      console.log('Verification failed. Invalid access token', err);
      reject("Unauthorized");
      return;
    }
    var checkRegex;
    let roles = payload.roles;
    if (!roles) {
      reject("Malformed token");
      return;
    }
    resolve(payload);
  });
};

function response(status, json, headers, callback) {
  var response = {
    status: JSON.stringify(status),
    headers: {
      "access-control-allow-origin": [{
        key: "Access-Control-Allow-Origin",
        value: headers.origin ? headers.origin[0].value : "*"
      }],
      "content-type": [{
        key: "Content-Type",
        value: "application/json"
      }],
      "content-encoding": [{
        key: "Content-Encoding",
        value: "UTF-8"
      }]
    }
  };
  if (status !== 204) {
    response["body"] = JSON.stringify(json);
  }
  callback(null, response);
}

exports.handler = (event, context, callback) => {
  const request = event.Records[0].cf.request;
  const headers = request.headers;
  request.queryStringParameters = querystring.decode(request.querystring || "");

  if (request.method === "OPTIONS") {
    var res = {
      status: "204",
      headers: {
        "access-control-allow-origin": [{
          key: "Access-Control-Allow-Origin",
          value: request.headers.origin ? request.headers.origin[0].value : "*"
        }],
        "access-control-allow-credentials": [{
          key: "Access-Control-Allow-Credentials",
          value: "true"
        }],
        "access-control-allow-methods": [{
          key: "Access-Control-Allow-Methods",
          value: "GET,HEAD,PUT,PATCH,POST,DELETE"
        }],
        "access-control-allow-headers": [{
          key: "Access-Control-Allow-Headers",
          value: request.headers["access-control-request-headers"] ?
            request.headers["access-control-request-headers"][0].value :
            "Authorization, Content-Type"
        }]
      }
    }
    callback(null, res);
    return;
  }

  const token = getToken(request);
  if (!token) {
    callback(null, request);
    return;
  }

  ValidateToken(token).then(payload => {
    const username = payload[jwtCouchUserNameField];
    let roles = payload[jwtCouchRoleField];
    if (!Array.isArray(roles)) {
      roles = [];
    }
    roles.push("user:" + username);
    const couchToken = crypto.createHmac("sha1", config.couchSecret).update(username).digest("hex");
    headers[CouchUserNameHeader.toLowerCase()] = [{
      key: CouchUserNameHeader,
      value: username
    }];
    headers[CouchRoleHeader.toLowerCase()] = [{
      key: CouchRoleHeader,
      value: roles.join(',')
    }];
    headers[CouchTokenHeader.toLowerCase()] = [{
      key: CouchTokenHeader,
      value: couchToken
    }];
    callback(null, request);
  }).catch(err => {
    // Remove current auth header
    if ("Authorization" in headers) {
      delete headers["Authorization"];
    }
    callback(null, request);
  });
};
