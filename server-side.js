"use strict";

var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var expressJwt = require('express-jwt');
var ethUtil = require('ethereumjs-util');
var sigUtil = require('eth-sig-util');
var jwt = require('jsonwebtoken');

module.exports = {};

module.exports.attach = function (app, secret) {
  // Don't accept non-AJAX requests to prevent XSRF attacks.
  app.use(function (req, res, next) {
    // if (!req.xhr) {
    //   res.status(500).send('Not AJAX');
    // } else {
    //   next();
    // }
    next();
  });

  app.use(bodyParser.json());
  app.use(cookieParser());

  app.use(expressJwt({
    secret: secret,
    credentialsRequired: false,
    getToken: function fromHeaderOrQuerystring(req) {
      if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
        return req.headers.authorization.split(' ')[1];
      } else if (req.query && req.query.token) {
        return req.query.token;
      }
      return null;
    }
  }).unless({
    path: ['/sign-in']
  }));

  app.post('/sign-in', function (req, res) {
    console.log(req.body);
    var baseUrl = req.protocol + "://" + req.hostname;
    var msgParams = {
      data: ethUtil.bufferToHex(Buffer.from("Sign into " + baseUrl, 'utf8')),
      sig: req.body.signed,
    };
    var recovered = sigUtil.recoverPersonalSignature(msgParams)
    if (recovered === req.body.account) {
      console.log('SigUtil Successfully verified signer as ' + req.body.account);

      var token = jwt.sign({
        loggedInAs: req.body.account
      }, secret);

      res.json({
        token
      })
    } else {
      res.json({
        token: 'error'
      })
      console.log('SigUtil unable to recover the message signer');
    }
  });
}
