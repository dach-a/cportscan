const jwt = require('jsonwebtoken');

const wss = new Map(); // Store WebSocket clients by scan ID

const handleWebSocket = (ws, req) => {
  // Optional: Verify token for WebSocket connection
  const token = req.headers['sec-websocket-protocol'];
  let user = null;

  if (token) {
    try {
      user = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      ws.close(4001, 'Unauthorized');
      return;
    }
  }

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      
      if (data.type === 'subscribe') {
        const scanId = data.scanId;
        if (!wss.has(scanId)) {
          wss.set(scanId, []);
        }
        wss.get(scanId).push(ws);
        ws.scanId = scanId;
      }
    } catch (error) {
      ws.send(JSON.stringify({ error: 'Invalid message format' }));
    }
  });

  ws.on('close', () => {
    if (ws.scanId && wss.has(ws.scanId)) {
      const clients = wss.get(ws.scanId);
      const index = clients.indexOf(ws);
      if (index > -1) {
        clients.splice(index, 1);
      }
    }
  });

  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
  });
};

const broadcastScanUpdate = (scanId, data) => {
  if (wss.has(scanId)) {
    const clients = wss.get(scanId);
    const message = JSON.stringify(data);
    clients.forEach(client => {
      if (client.readyState === 1) { // OPEN
        client.send(message);
      }
    });
  }
};

const removeScanClients = (scanId) => {
  if (wss.has(scanId)) {
    wss.delete(scanId);
  }
};

module.exports = {
  handleWebSocket,
  broadcastScanUpdate,
  removeScanClients
};
