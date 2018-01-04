module.exports = {
  jwt: {
    secret: "iamveryscrecet",
    issuer: "https://api.mydomain.com",
    couchUserField: "sub",
    couchRolesField: "roles"
  },
  couchdb: {
    secret: "have a look at http://docs.couchdb.org/en/latest/config/auth.html#couch_httpd_auth/secret",
    usernameHeader: "X-Auth-CouchDB-UserName",
    rolesHeader: "X-Auth-CouchDB-Roles",
    tokenHeader: "X-Auth-CouchDB-Token"
  },
  disableCookie: false, // disables the use of the jwt_token cookie to authenticate
  disableQueryString: false, // disables the use of the ?token= query string parameter to authenticate
  disableAuthHeader: false // disables the use of the Authorization: Bearer <token> header to authenticate
}
