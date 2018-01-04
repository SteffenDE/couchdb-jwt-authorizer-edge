"use strict";

const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const querystring = require("querystring");
const config = require("./config");

if (!(config.jwt && config.jwt.secret) || !(config.couchdb && config.couchdb.secret)) {
  throw new Error("config.jwt and config.couchdb must be provided correctly in config.js!");
}

function parseCookies(cookiestring) {
  var list = {};
  var rc = cookiestring;

  rc && rc.split(";").forEach(function( cookie ) {
    var parts = cookie.split("=");
    list[parts[0].trim()] = decodeURI(parts.slice(1).join("="));
  });

  return list;
}

function getToken(request) {
  const queryStringParameters = querystring.decode(request.querystring || "");
  const headers = request.headers;
  let token;
  if (headers) {
    if (headers.authorization && !config.disableAuthHeader) {
      let bearerHeader = headers.authorization[0].value;
      let splitted = bearerHeader.split(" ");
      if (splitted.length !== 2 || !/^Bearer$/i.test(splitted[0])) {
        return;
      }
      else {
        token = splitted[1];
      }
    }
    else if (headers.cookie && !config.disableCookie) {
      for (let i = 0; i < headers.cookie.length; i++) {
        let parsedCookies = parseCookies(headers.cookie[i].value);
        if (Object.keys(parsedCookies).indexOf("jwt_token") >= 0) {
          token = parsedCookies["jwt_token"];
          break;
        }
      }
    }
  }
  if (queryStringParameters["token"] && !config.disableQueryString) {
    token = queryStringParameters["token"];
    delete queryStringParameters.token;
    request.queryString = querystring.encode(queryStringParameters);
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
    if (decodedJwt.payload.iss != config.jwt.issuer) {
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

    let payload;
    try {
      payload = jwt.verify(token, config.jwt.secret, { issuer: config.jwt.issuer });
    }
    catch(err) {
      console.log("Verification failed. Invalid access token", err);
      reject("Unauthorized");
      return;
    }
    if (!payload[config.jwt.couchRolesField]) {
      reject("Malformed token");
      return;
    }
    resolve(payload);
  });
}

exports.handler = (event, context, callback) => {
  const request = event.Records[0].cf.request;
  const headers = request.headers;
  request.queryStringParameters = querystring.decode(request.querystring || "");

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
    };
    callback(null, res);
    return;
  }

  const token = getToken(request);
  if (!token) {
    callback(null, request);
    return;
  }

  ValidateToken(token).then(payload => {
    const username = payload[config.jwt.couchUserField];
    let roles = payload[config.jwt.couchRolesField];
    if (!Array.isArray(roles)) {
      roles = [];
    }
    roles.push("user:" + username);
    const couchToken = crypto.createHmac("sha1", config.couchdb.secret).update(username).digest("hex");
    headers[config.couchdb.usernameHeader.toLowerCase()] = [{
      key: config.couchdb.usernameHeader,
      value: username
    }];
    headers[config.couchdb.rolesHeader.toLowerCase()] = [{
      key: config.couchdb.rolesHeader,
      value: roles.join(",")
    }];
    headers[config.couchdb.tokenHeader.toLowerCase()] = [{
      key: config.couchdb.tokenHeader,
      value: couchToken
    }];
    callback(null, request);
  }).catch(err => {
    // Remove current auth header
    console.log("Error setting couch headers. Forwarding request anyway...", err);
    if ("Authorization" in headers) {
      delete headers["Authorization"];
    }
    callback(null, request);
  });
};
