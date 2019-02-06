/*!
 * Copyright (c) 2018-2019 Veres One Project. All rights reserved.
 */
const axios = require('axios');
const https = require('https');

const strictSSL = false;

const api = {};
module.exports = api;

api.getTicketServiceProof = async ({operation, ticketService}) => {
  const result = await axios({
    data: {operation},
    httpsAgent: new https.Agent({rejectUnauthorized: strictSSL}),
    method: 'POST',
    url: ticketService,
  });
  return result.data;
};
