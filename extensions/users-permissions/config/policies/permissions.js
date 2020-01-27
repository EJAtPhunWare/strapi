const jsonWebToken = require('jsonwebtoken');

const JWT_SECRET = '';
const jwtRequiredClaims = ['id', 'email', 'first_name', 'last_name', 'orgs', 'org_id', 'org_name', 'session_id'];
const getJwt = req => {
  const jwt = req.headers.authorization || req.cookies.maas_jwt || '';
  return ~jwt.indexOf('Bearer') ? jwt.split(' ')[1] : jwt;
};

module.exports = async (ctx, next) => {
  const res = ctx.request;
  if (res && res.header && res.header.authorization) {
    try {
      let jwt = getJwt(res);
      jsonWebToken.verify(jwt, JWT_SECRET, (err, decoded) => {
        if (err || !decoded) {
          if (err)
            return res
              .status(401)
              .jsonp({ status: 'access denied', msg: err.message });
          if (!decoded)
            return res
              .status(401)
              .jsonp({ status: 'access denied', msg: 'error decoding token' });
        }

        if (
          jwtRequiredClaims.filter(prop => !decoded.hasOwnProperty(prop)).length
        ) {
          return res
            .status(401)
            .jsonp({ status: 'access denied', msg: 'invalid token payload' });
        }

        req.user = decoded;
        return next();
      });
    } catch (err) {
      return handleErrors(ctx, err, 'unauthorized');
    }
  }
};
