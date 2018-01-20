# couchdb-jwt-authorizer@edge

[![Greenkeeper badge](https://badges.greenkeeper.io/SteffenDE/couchdb-jwt-authorizer-edge.svg)](https://greenkeeper.io/)
Uses AWS Lambda@Edge + Cloudfront to use JWT tokens with CouchDB. 

This enables using a CouchDB (Cluster/Standalone) Server which is used as CloudFront origin to authenticate users using [JSON Web Tokens](https://jwt.io/).
As a result you can use the same authentication mechanism for your API and your database (at least that's what I wanted to do).

# config.js
The config file needs the JWT secret to verify that the tokens are valid. If they are, the script adds Couch-Proxy-Auth headers to the backend request.
Therefore it needs the CouchDB-Secret (see http://docs.couchdb.org/en/latest/config/auth.html#couch_httpd_auth/secret - at least that's strongly recommended).
