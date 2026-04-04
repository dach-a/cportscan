require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
const expressWs = require('express-ws');
const { initializeTables } = require('./db/database');
const { handleWebSocket, broadcastScanUpdate } = require('./middleware/websocket');
const authRoutes = require('./routes/auth');
const scanRoutes = require('./routes/scans');

const app = express();
const PORT = process.env.PORT || 3000;

// WebSocket support
expressWs(app);

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Initialize database
initializeTables().catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/scans', scanRoutes);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    version: '2.0.0'
  });
});

// WebSocket endpoint
app.ws('/ws/:scanId', (ws, req) => {
  const scanId = req.params.scanId;
  
  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg);
      if (data.type === 'subscribe') {
        ws.scanId = scanId;
        ws.send(JSON.stringify({ 
          type: 'subscribed', 
          scanId,
          message: 'Connected to scan updates'
        }));
      }
    } catch (error) {
      ws.send(JSON.stringify({ error: 'Invalid message' }));
    }
  });

  ws.on('close', () => {
    console.log(`Client disconnected from scan ${scanId}`);
  });

  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
  });
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════╗
║        🚀 cportscan-web v2.0.0 Running             ║
║════════════════════════════════════════════════════║
║  📊 Dashboard: http://localhost:${PORT}            ║
║  📡 WebSocket: ws://localhost:${PORT}/ws/:scanId   ║
║  📚 API Docs: http://localhost:${PORT}/api         ║
║  🔐 Auth: Username/Password required               ║
║════════════════════════════════════════════════════║
  `);
});
