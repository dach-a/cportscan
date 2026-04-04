const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { v4: uuidv4 } = require('uuid');
const { spawn } = require('child_process');
const path = require('path');
const net = require('net');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Store scan jobs in memory (in production, use a database)
const scanJobs = new Map();

// Configuration
const CONFIG = {
  MAX_PORTS: 1000,
  MAX_CONCURRENT_SCANS: 5,
  SCAN_TIMEOUT: 30000, // 30 seconds per port
  RATE_LIMIT: {
    max_scans_per_hour: 10,
    max_ports_per_scan: 1000
  },
  BLOCKED_PORTS: [1, 20, 21, 22, 23, 25, 53, 67, 68, 123], // Restricted ports
  BLOCKED_IPS: ['127.0.0.1', 'localhost', '0.0.0.0', '::1'] // Blocked IPs
};

let activeScanCount = 0;
const clientRateLimits = new Map();

// Utility: Validate IP address
function isValidIP(ip) {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^([\da-f]{0,4}:){2,7}[\da-f]{0,4}$/i;
  
  if (ipv4Regex.test(ip)) {
    const parts = ip.split('.');
    return parts.every(part => parseInt(part) <= 255);
  }
  return ipv6Regex.test(ip);
}

// Utility: Check if IP is blocked
function isBlockedIP(ip) {
  return CONFIG.BLOCKED_IPS.includes(ip);
}

// Utility: Check if port is restricted
function isRestrictedPort(port) {
  return CONFIG.BLOCKED_PORTS.includes(port);
}

// Utility: Rate limiting
function checkRateLimit(clientIP) {
  const now = Date.now();
  const oneHourAgo = now - (60 * 60 * 1000);
  
  if (!clientRateLimits.has(clientIP)) {
    clientRateLimits.set(clientIP, []);
  }
  
  const times = clientRateLimits.get(clientIP).filter(t => t > oneHourAgo);
  clientRateLimits.set(clientIP, times);
  
  if (times.length >= CONFIG.RATE_LIMIT.max_scans_per_hour) {
    return false;
  }
  
  times.push(now);
  return true;
}

// Utility: Generate port range
function generatePortRange(startPort, endPort) {
  const ports = [];
  const start = Math.max(1, parseInt(startPort));
  const end = Math.min(65535, parseInt(endPort));
  
  if (end - start + 1 > CONFIG.MAX_PORTS) {
    return null; // Exceeds max ports
  }
  
  for (let i = start; i <= end; i++) {
    if (!isRestrictedPort(i)) {
      ports.push(i);
    }
  }
  
  return ports;
}

// Utility: Scan port using Node.js net module
function scanPort(host, port, timeout = 1000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const timer = setTimeout(() => {
      socket.destroy();
      resolve(false);
    }, timeout);
    
    socket.on('connect', () => {
      clearTimeout(timer);
      socket.destroy();
      resolve(true);
    });
    
    socket.on('error', () => {
      clearTimeout(timer);
      resolve(false);
    });
    
    socket.connect(port, host);
  });
}

// API Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Initiate a port scan
app.post('/api/scan', async (req, res) => {
  try {
    const { hostname, startPort, endPort } = req.body;
    const clientIP = req.ip;
    
    // Validation
    if (!hostname || startPort === undefined || endPort === undefined) {
      return res.status(400).json({ error: 'Missing required fields: hostname, startPort, endPort' });
    }
    
    if (!isValidIP(hostname) && !/^[a-zA-Z0-9.-]+$/.test(hostname)) {
      return res.status(400).json({ error: 'Invalid hostname format' });
    }
    
    if (isBlockedIP(hostname)) {
      return res.status(403).json({ error: 'Scanning this address is not permitted' });
    }
    
    if (!checkRateLimit(clientIP)) {
      return res.status(429).json({ error: 'Rate limit exceeded. Max 10 scans per hour.' });
    }
    
    if (activeScanCount >= CONFIG.MAX_CONCURRENT_SCANS) {
      return res.status(503).json({ error: 'Server busy. Too many concurrent scans.' });
    }
    
    const ports = generatePortRange(startPort, endPort);
    if (!ports) {
      return res.status(400).json({ error: `Port range exceeds maximum of ${CONFIG.MAX_PORTS} ports` });
    }
    
    // Create scan job
    const scanId = uuidv4();
    const scanJob = {
      id: scanId,
      hostname,
      startPort: Math.max(1, parseInt(startPort)),
      endPort: Math.min(65535, parseInt(endPort)),
      ports,
      status: 'pending',
      results: [],
      progress: 0,
      startTime: new Date(),
      endTime: null,
      error: null
    };
    
    scanJobs.set(scanId, scanJob);
    activeScanCount++;
    
    // Start scan asynchronously
    performScan(scanId);
    
    res.json({ scanId, status: 'initiated', message: 'Scan started' });
  } catch (error) {
    console.error('Error initiating scan:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get scan status
app.get('/api/scan/:scanId', (req, res) => {
  const { scanId } = req.params;
  
  if (!scanJobs.has(scanId)) {
    return res.status(404).json({ error: 'Scan not found' });
  }
  
  const job = scanJobs.get(scanId);
  res.json({
    id: job.id,
    hostname: job.hostname,
    status: job.status,
    progress: job.progress,
    results: job.results,
    startTime: job.startTime,
    endTime: job.endTime,
    error: job.error
  });
});

// Get all recent scans
app.get('/api/scans', (req, res) => {
  const scans = Array.from(scanJobs.values()).map(job => ({
    id: job.id,
    hostname: job.hostname,
    status: job.status,
    progress: job.progress,
    portsScanned: job.ports.length,
    openPorts: job.results.filter(r => r.open).length,
    startTime: job.startTime,
    endTime: job.endTime
  }));
  
  res.json(scans);
});

// Perform the actual scan
async function performScan(scanId) {
  const job = scanJobs.get(scanId);
  
  try {
    job.status = 'scanning';
    const ports = job.ports;
    
    // Scan ports sequentially with progress updates
    for (let i = 0; i < ports.length; i++) {
      const port = ports[i];
      const isOpen = await scanPort(job.hostname, port, CONFIG.SCAN_TIMEOUT);
      
      job.results.push({
        port,
        open: isOpen,
        status: isOpen ? 'open' : 'closed'
      });
      
      job.progress = Math.round(((i + 1) / ports.length) * 100);
    }
    
    job.status = 'completed';
    job.endTime = new Date();
  } catch (error) {
    job.status = 'failed';
    job.error = error.message;
    job.endTime = new Date();
    console.error(`Scan ${scanId} failed:`, error);
  } finally {
    activeScanCount--;
  }
}

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
  console.log(`🚀 cportscan-web server running on http://localhost:${PORT}`);
  console.log(`📊 Dashboard available at http://localhost:${PORT}`);
});
