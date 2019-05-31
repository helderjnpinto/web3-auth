"use strict";

var Web3 = require('web3');
var Eth = require('ethjs');
var ethUtil = require('ethereumjs-util');
var $ = require('jquery');

module.exports = {};

module.exports.signIn = function () {

  window.Eth = Eth;
  // window.web3 = new Web3(web3.currentProvider);

  let web3Provider = null


  // Modern dapp browsers...
  if (window.ethereum) {
    web3Provider = window.ethereum;

    try {
      // Request account access
      window.ethereum.enable().then(address => {
        console.log("TCL: address", address)
        window.metaMaskCoinbase = address
        loadApp(web3Provider, address)
      }).catch(error => {
        console.log("TCL: .enable() error: ", error)
      })
    } catch (error) {
      // User denied account access...
      console.error("User denied account access")
    }
  } else if (window.web3) {
    // Legacy dapp browsers...
    console.log("TCL: Legacy dapp browsers")
    web3Provider = window.web3.currentProvider;
    loadApp(web3Provider)
  } else {
    // If no injected web3 instance is detected, fall back to Ganache
    console.log("TCL: using localhost")
    web3Provider = new Web3.providers.HttpProvider('http://localhost:8545');
    loadApp(web3Provider)
  }


}


function loadApp(web3Provider, address) {
  const legacyOptions = {
    defaultBlock: 'latest'
  }

  const newOptions = {
    defaultAccount: address,
    defaultBlock: 'latest',
    defaultGas: 1,
    defaultGasPrice: 0,
    transactionBlockTimeout: 50,
    transactionConfirmationBlocks: 1,
    transactionPollingTimeout: 480,
  }

  const _options = !address ? newOptions : legacyOptions

  const web3 = new Web3(web3Provider, null, _options);
  window.web3 = web3

  var eth = new Eth(web3.currentProvider)
  console.log("TCL: loadApp -> eth", eth)

  var baseUrl = location.protocol + "//" + location.hostname;
  console.log("TCL: loadApp -> baseUrl", baseUrl)

  console.log("TCL: loadApp -> web3.eth.accounts[0]", web3.eth.accounts[0])
  eth.personal_sign(web3.eth.accounts[0], ethUtil.bufferToHex(new Buffer("Sign into " + baseUrl, 'utf8')))
    .then((signed) => {
      console.log('Signed!  Result is: ', signed);

      $.ajax({
        method: 'POST',
        contentType: 'application/json',
        url: baseUrl + ":" + location.port + '/sign-in',
        data: JSON.stringify({
          account: web3.eth.accounts[0],
          signed: signed,
        }),
        success: function (data, textStatus, jqXHR) {
          console.log('Signed in.');
        },
        error: function (jqXHR, textStatus, errorThrown) {
          console.log('Failed to sign in.');
        }
      });
    })
}
