/*!
 * Copyright (c) 2018-2019 Veres One Project. All rights reserved.
 */
const axios = require('axios');
const https = require('https');

const strictSSL = false;

const api = {};
module.exports = api;

const ledgerAgentCache = new Map();

api.getLedgerAgentStatus = async ({hostname}) => {
  if(ledgerAgentCache.has(hostname)) {
    return ledgerAgentCache.get(hostname);
  }
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
  ledgerAgentCache.set(hostname, result2.data);
  return result2.data;
};

api.getTargetNode = async ({hostname}) => {
  const {targetNode} = await api.getLedgerAgentStatus({hostname});
  return targetNode;
};

api.getTicketServiceEndpoint = async ({hostname}) =>
  (await api.getLedgerAgentStatus({hostname})).service[
    'urn:veresone:ticket-service'].id;

api.getTicketServiceProof = async ({hostname, operation}) => {
  const ticketService = await api.getTicketServiceEndpoint({hostname});
  const result = await axios({
    data: {operation},
    httpsAgent: new https.Agent({rejectUnauthorized: strictSSL}),
    method: 'POST',
    url: ticketService,
  });
  return result.data;
};
