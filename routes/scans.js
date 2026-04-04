const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { dbGet, dbRun, dbAll } = require('../db/database');
const { verifyToken, optionalAuth } = require('../middleware/auth');
const { broadcastScanUpdate, removeScanClients } = require('../middleware/websocket');
const net = require('net');

const router = express.Router();

const CONFIG = {
  MAX_PORTS: parseInt(process.env.MAX_PORTS) || 1000,
  MAX_CONCURRENT_SCANS: parseInt(process.env.MAX_CONCURRENT_SCANS) || 5,
  SCAN_TIMEOUT: parseInt(process.env.SCAN_TIMEOUT) || 30000,
  BLOCKED_PORTS: [1, 20, 21, 22, 23, 25, 53, 67, 68, 123],
  BLOCKED_IPS: ['127.0.0.1', 'localhost', '0.0.0.0', '::1']
};

let activeScanCount = 0;
const clientRateLimits = new Map();

// Utility functions
function isValidIP(ip) {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^([\da-f]{0,4}:){2,7}[\da-f]{0,4}$/i;
  
  if (ipv4Regex.test(ip)) {
    const parts = ip.split('.');
    return parts.every(part => parseInt(part) <= 255);
  }
  return ipv6Regex.test(ip);
}

function isValidHostname(hostname) {
  return /^[a-zA-Z0-9.-]+$/.test(hostname);
}

function isBlockedIP(ip) {
  return CONFIG.BLOCKED_IPS.includes(ip);
}

function isRestrictedPort(port) {
  return CONFIG.BLOCKED_PORTS.includes(port);
}

function checkRateLimit(clientId) {
  const now = Date.now();
  const oneHourAgo = now - (60 * 60 * 1000);
  
  if (!clientRateLimits.has(clientId)) {
    clientRateLimits.set(clientId, []);
  }
  
  const times = clientRateLimits.get(clientId).filter(t => t > oneHourAgo);
  clientRateLimits.set(clientId, times);
  
  const maxScans = parseInt(process.env.RATE_LIMIT_SCANS_PER_HOUR) || 20;
  if (times.length >= maxScans) {
    return false;
  }
  
  times.push(now);
  return true;
}

function generatePortRange(startPort, endPort) {
  const ports = [];
  const start = Math.max(1, parseInt(startPort));
  const end = Math.min(65535, parseInt(endPort));
  
  if (end - start + 1 > CONFIG.MAX_PORTS) {
    return null;
  }
  
  for (let i = start; i <= end; i++) {
    if (!isRestrictedPort(i)) {
      ports.push(i);
    }
  }
  
  return ports;
}

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

// Start a scan (single target)
router.post('/scan', optionalAuth, async (req, res) => {
  try {
    const { hostname, startPort, endPort } = req.body;
    const clientId = req.user?.id || req.ip;
    
    if (!hostname || startPort === undefined || endPort === undefined) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    if (!isValidIP(hostname) && !isValidHostname(hostname)) {
      return res.status(400).json({ error: 'Invalid hostname format' });
    }
    
    if (isBlockedIP(hostname)) {
      return res.status(403).json({ error: 'Scanning this address is not permitted' });
    }
    
    if (!checkRateLimit(clientId)) {
      const maxScans = parseInt(process.env.RATE_LIMIT_SCANS_PER_HOUR) || 20;
      return res.status(429).json({ error: `Rate limit exceeded. Max ${maxScans} scans per hour.` });
    }
    
    if (activeScanCount >= CONFIG.MAX_CONCURRENT_SCANS) {
      return res.status(503).json({ error: 'Server busy. Too many concurrent scans.' });
    }
    
    const ports = generatePortRange(startPort, endPort);
    if (!ports) {
      return res.status(400).json({ error: `Port range exceeds maximum of ${CONFIG.MAX_PORTS} ports` });
    }
    
    const scanId = uuidv4();
    const startTime = new Date();
    
    // Save scan to database
    await dbRun(
      `INSERT INTO scans (id, user_id, hostname, start_port, end_port, total_ports_count, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [scanId, req.user?.id || null, hostname, parseInt(startPort), parseInt(endPort), ports.length, startTime]
    );
    
    activeScanCount++;
    performScan(scanId, hostname, ports, startTime);
    
    res.json({ scanId, status: 'initiated', message: 'Scan started' });
  } catch (error) {
    console.error('Scan error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Start multi-target scan
router.post('/scan/batch', verifyToken, async (req, res) => {
  try {
    const { targets, startPort, endPort } = req.body;
    
    if (!targets || !Array.isArray(targets) || targets.length === 0) {
      return res.status(400).json({ error: 'targets must be a non-empty array' });
    }
    
    if (targets.length > 10) {
      return res.status(400).json({ error: 'Maximum 10 targets per batch' });
    }
    
    const clientId = req.user.id;
    if (!checkRateLimit(clientId)) {
      return res.status(429).json({ error: 'Rate limit exceeded' });
    }
    
    const scanIds = [];
    
    for (const hostname of targets) {
      if (!isValidIP(hostname) && !isValidHostname(hostname)) {
        continue;
      }
      
      if (isBlockedIP(hostname)) {
        continue;
      }
      
      const ports = generatePortRange(startPort, endPort);
      if (!ports) continue;
      
      const scanId = uuidv4();
      const startTime = new Date();
      
      await dbRun(
        `INSERT INTO scans (id, user_id, hostname, start_port, end_port, total_ports_count, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [scanId, clientId, hostname, parseInt(startPort), parseInt(endPort), ports.length, startTime]
      );
      
      activeScanCount++;
      performScan(scanId, hostname, ports, startTime);
      scanIds.push(scanId);
    }
    
    res.json({ scanIds, message: `${scanIds.length} scans initiated` });
  } catch (error) {
    console.error('Batch scan error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get scan status
router.get('/scan/:scanId', optionalAuth, async (req, res) => {
  try {
    const { scanId } = req.params;
    
    const scan = await dbGet('SELECT * FROM scans WHERE id = ?', [scanId]);
    
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    
    const results = await dbAll(
      'SELECT port, status FROM scan_results WHERE scan_id = ? ORDER BY port ASC',
      [scanId]
    );
    
    res.json({
      id: scan.id,
      hostname: scan.hostname,
      status: scan.status,
      progress: scan.progress,
      portRange: `${scan.start_port}-${scan.end_port}`,
      results,
      openPortsCount: scan.open_ports_count,
      totalPortsCount: scan.total_ports_count,
      scanTimeSeconds: scan.scan_time_seconds,
      createdAt: scan.created_at,
      completedAt: scan.completed_at,
      error: scan.error_message
    });
  } catch (error) {
    console.error('Error fetching scan:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user's scan history
router.get('/history', verifyToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;
    
    const scans = await dbAll(
      `SELECT id, hostname, status, progress, open_ports_count, total_ports_count, 
              scan_time_seconds, created_at, completed_at
       FROM scans WHERE user_id = ?
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [req.user.id, limit, offset]
    );
    
    const countResult = await dbGet(
      'SELECT COUNT(*) as total FROM scans WHERE user_id = ?',
      [req.user.id]
    );
    
    res.json({
      scans,
      pagination: {
        page,
        limit,
        total: countResult.total,
        pages: Math.ceil(countResult.total / limit)
      }
    });
  } catch (error) {
    console.error('Error fetching history:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all recent scans (public)
router.get('/all', async (req, res) => {
  try {
    const limit = 50;
    const scans = await dbAll(
      `SELECT id, hostname, status, progress, open_ports_count, total_ports_count, created_at
       FROM scans ORDER BY created_at DESC LIMIT ?`,
      [limit]
    );
    
    res.json(scans);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Perform the actual scan
async function performScan(scanId, hostname, ports, startTime) {
  try {
    await dbRun('UPDATE scans SET status = ? WHERE id = ?', ['scanning', scanId]);
    
    let openCount = 0;
    
    for (let i = 0; i < ports.length; i++) {
      const port = ports[i];
      const isOpen = await scanPort(hostname, port, CONFIG.SCAN_TIMEOUT);
      
      const status = isOpen ? 'open' : 'closed';
      await dbRun(
        'INSERT INTO scan_results (scan_id, port, status) VALUES (?, ?, ?)',
        [scanId, port, status]
      );
      
      if (isOpen) openCount++;
      
      const progress = Math.round(((i + 1) / ports.length) * 100);
      
      // Broadcast update via WebSocket
      broadcastScanUpdate(scanId, {
        type: 'progress',
        scanId,
        progress,
        port,
        portStatus: status,
        openCount
      });
      
      // Update database progress
      await dbRun(
        'UPDATE scans SET progress = ?, open_ports_count = ? WHERE id = ?',
        [progress, openCount, scanId]
      );
    }
    
    const endTime = new Date();
    const scanTimeSeconds = (endTime - startTime) / 1000;
    
    await dbRun(
      'UPDATE scans SET status = ?, completed_at = ?, scan_time_seconds = ? WHERE id = ?',
      ['completed', endTime, scanTimeSeconds, scanId]
    );
    
    broadcastScanUpdate(scanId, {
      type: 'completed',
      scanId,
      status: 'completed',
      openCount,
      scanTimeSeconds
    });
    
    removeScanClients(scanId);
  } catch (error) {
    await dbRun(
      'UPDATE scans SET status = ?, error_message = ? WHERE id = ?',
      ['failed', error.message, scanId]
    );
    
    broadcastScanUpdate(scanId, {
      type: 'error',
      scanId,
      error: error.message
    });
    
    console.error(`Scan ${scanId} failed:`, error);
  } finally {
    activeScanCount--;
  }
}

module.exports = router;
