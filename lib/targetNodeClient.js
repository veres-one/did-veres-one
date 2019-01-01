/*!
 * Copyright (c) 2018-2019 Veres One Project. All rights reserved.
 */
const axios = require('axios');
const https = require('https');

const strictSSL = false;

const api = {};
module.exports = api;

api.getTargetNode = async ({hostname}) => {
  const url = `https://${hostname}/ledger-agents`;
  const result = await axios({
    httpsAgent: new https.Agent({rejectUnauthorized: strictSSL}),
    method: 'GET',
    url,
  });
  const [ledgerAgent] = result.data.ledgerAgent;
  const {service: {ledgerAgentStatusService}} = ledgerAgent;
  const result2 = await axios({
    httpsAgent: new https.Agent({rejectUnauthorized: strictSSL}),
    method: 'GET',
    url: ledgerAgentStatusService,
  });
  const {targetNode} = result2.data;
  return targetNode;
};
