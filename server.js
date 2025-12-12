// ============================================
// VR THERAPY SERVER - HANDLES ENCRYPTED DATA
// ============================================
// This server receives encrypted sensor data from clients,
// performs homomorphic operations without decryption,
// and stores encrypted data for later retrieval by clinicians

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const fs = require('fs').promises;
const path = require('path');
const paillier = require('paillier-bigint');
const crypto = require('crypto');

// ============================================
// SERVER CONFIGURATION
// ============================================
const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data', 'sessions.json');

// ============================================
// MIDDLEWARE
// ============================================
app.use(cors()); // Allow cross-origin requests
app.use(bodyParser.json({ limit: '50mb' })); // Parse JSON bodies (large limit for encrypted data)

// Logging middleware
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    next();
});

// ============================================
// DATA STORAGE UTILITIES
// ============================================

// Initialize data file if it doesn't exist
async function initializeDataFile() {
    try {
        // Create data directory if it doesn't exist
        const dataDir = path.dirname(DATA_FILE);
        await fs.mkdir(dataDir, { recursive: true });
        
        // Check if file exists
        try {
            await fs.access(DATA_FILE);
        } catch {
            // File doesn't exist, create it
            await fs.writeFile(DATA_FILE, JSON.stringify({ sessions: {} }, null, 2));
            console.log('✓ Data file initialized');
        }
    } catch (error) {
        console.error('Error initializing data file:', error);
    }
}

// Read all session data
async function readSessionData() {
    try {
        const data = await fs.readFile(DATA_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Error reading session data:', error);
        return { sessions: {} };
    }
}

// Write session data
async function writeSessionData(data) {
    try {
        await fs.writeFile(DATA_FILE, JSON.stringify(data, null, 2));
    } catch (error) {
        console.error('Error writing session data:', error);
        throw error;
    }
}

// ============================================
// DATA VALIDATION
// ============================================

// Validate incoming encrypted data
function validateEncryptedData(dataPackage) {
    // Check required fields
    if (!dataPackage.sessionId) {
        return { valid: false, error: 'Missing sessionId' };
    }
    
    if (!dataPackage.timestamp) {
        return { valid: false, error: 'Missing timestamp' };
    }
    
    if (!dataPackage.encryptedData) {
        return { valid: false, error: 'Missing encryptedData' };
    }
    
    if (!dataPackage.publicKey || !dataPackage.publicKey.n || !dataPackage.publicKey.g) {
        return { valid: false, error: 'Missing or invalid publicKey' };
    }
    
    // Check encrypted data structure
    const requiredFields = ['alpha', 'beta', 'gamma', 'heartRate'];
    for (const field of requiredFields) {
        if (!dataPackage.encryptedData[field]) {
            return { valid: false, error: `Missing encrypted field: ${field}` };
        }
    }
    
    // Validate that encrypted values are valid BigInt strings
    try {
        for (const field of requiredFields) {
            BigInt(dataPackage.encryptedData[field]);
        }
    } catch (error) {
        return { valid: false, error: 'Invalid encrypted value format' };
    }
    
    return { valid: true };
}

// Calculate hash for integrity check
function calculateHash(data) {
    const str = JSON.stringify(data); // Convert encryptedData object to string
    const hash = crypto.createHash('sha256') // SHA-256 hash
                       .update(str)
                       .digest('hex'); // Hexadecimal string
    return hash;
}

// Verify the integrity of a sample
function verifyIntegrity(sample) {
    if (!sample.encryptedData || !sample.integrityHash) return false;
    const recomputedHash = calculateHash(sample.encryptedData);
    return recomputedHash === sample.integrityHash;
}

// ============================================
// HOMOMORPHIC OPERATIONS
// ============================================

// Perform homomorphic addition on encrypted values
function homomorphicAdd(encryptedValue1, encryptedValue2, publicKey) {
    try {
        // Recreate public key from stored values
        const pubKey = new paillier.PublicKey(
            BigInt(publicKey.n),
            BigInt(publicKey.g)
        );
        
        // Convert encrypted strings to BigInts
        const encrypted1 = BigInt(encryptedValue1);
        const encrypted2 = BigInt(encryptedValue2);
        
        // Perform homomorphic addition
        const result = pubKey.addition(encrypted1, encrypted2);
        
        return result.toString();
    } catch (error) {
        console.error('Homomorphic addition error:', error);
        return null;
    }
}

// Calculate average of encrypted values
function homomorphicAverage(encryptedValues, publicKey, count) {
    try {
        // Recreate public key
        const pubKey = new paillier.PublicKey(
            BigInt(publicKey.n),
            BigInt(publicKey.g)
        );
        
        // Sum all encrypted values using homomorphic addition
        let sum = BigInt(encryptedValues[0]);
        for (let i = 1; i < encryptedValues.length; i++) {
            sum = pubKey.addition(sum, BigInt(encryptedValues[i]));
        }
        
        // Note: Division is not directly supported in Paillier
        // We return the sum and let the client divide after decryption
        // Alternatively, we could multiply by (1/count) before encryption
        
        return {
            sum: sum.toString(),
            count: count,
            note: 'Divide decrypted sum by count to get average'
        };
    } catch (error) {
        console.error('Homomorphic average error:', error);
        return null;
    }
}

// Normalize encrypted data (multiply by constant)
function homomorphicMultiply(encryptedValue, scalar, publicKey) {
    try {
        const pubKey = new paillier.PublicKey(
            BigInt(publicKey.n),
            BigInt(publicKey.g)
        );
        
        const encrypted = BigInt(encryptedValue);
        
        // Homomorphic scalar multiplication
        const result = pubKey.multiply(encrypted, BigInt(scalar));
        
        return result.toString();
    } catch (error) {
        console.error('Homomorphic multiplication error:', error);
        return null;
    }
}

// ============================================
// API ROUTES
// ============================================

// POST /api/data - Receive encrypted sensor data
app.post('/api/data', async (req, res) => {
    try {
        const dataPackage = req.body;
        
        console.log('📦 Received encrypted data package');
        console.log('   Session ID:', dataPackage.sessionId);
        console.log('   Timestamp:', dataPackage.timestamp);
        
        // Validate data
        const validation = validateEncryptedData(dataPackage);
        if (!validation.valid) {
            console.error('❌ Validation failed:', validation.error);
            return res.status(400).json({ 
                success: false, 
                error: validation.error 
            });
        }
        
        // Calculate integrity hash
        const integrityHash = calculateHash(dataPackage.encryptedData);
        
        // Read existing data
        const allData = await readSessionData();
        
        // Initialize session if it doesn't exist
        if (!allData.sessions[dataPackage.sessionId]) {
            allData.sessions[dataPackage.sessionId] = {
                sessionId: dataPackage.sessionId,
                startTime: dataPackage.timestamp,
                publicKey: dataPackage.publicKey,
                samples: [],
                statistics: null
            };
            console.log('✓ New session created:', dataPackage.sessionId);
        }
        
        // Add encrypted sample with integrity hash
        allData.sessions[dataPackage.sessionId].samples.push({
            timestamp: dataPackage.timestamp,
            encryptedData: dataPackage.encryptedData,
            integrityHash: integrityHash
        });
        
        // Perform homomorphic operations on the encrypted data
        const session = allData.sessions[dataPackage.sessionId];
        const samples = session.samples;
        
        if (samples.length >= 2) {
            // Filter out any tampered samples
            const validSamples = samples.filter(verifyIntegrity);

            // Calculate encrypted average heart rate
            const heartRateValues = validSamples.map(s => s.encryptedData.heartRate);
            const avgHeartRate = homomorphicAverage(
                heartRateValues,
                dataPackage.publicKey,
                heartRateValues.length
            );
            
            // Store statistics (still encrypted)
            session.statistics = {
                sampleCount: validSamples.length,
                encryptedAvgHeartRate: avgHeartRate,
                lastUpdated: dataPackage.timestamp
            };
            
            console.log('📊 Computed encrypted statistics (sample count: ${validSamples.length})');
        }
        
        // Save updated data
        await writeSessionData(allData);
        
        console.log('✓ Data stored successfully (sample #' + samples.length + ')');
        console.log('⚠️  Server never saw plaintext values - all data remains encrypted!');
        
        res.json({ 
            success: true, 
            message: 'Encrypted data received and stored',
            sampleCount: samples.length
        });
        
    } catch (error) {
        console.error('❌ Error processing data:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Internal server error' 
        });
    }
});

// GET /api/data/:sessionId - Retrieve encrypted session data
app.get('/api/data/:sessionId', async (req, res) => {
    try {
        const sessionId = req.params.sessionId;
        
        console.log('📥 Request for session data:', sessionId);
        
        // Read session data
        const allData = await readSessionData();
        const sessionData = allData.sessions[sessionId];
        
        if (!sessionData) {
            console.log('❌ Session not found:', sessionId);
            return res.status(404).json({ 
                success: false, 
                error: 'Session not found' 
            });
        }
        
        console.log('✓ Returning encrypted data (', sessionData.samples.length, 'samples)');
        console.log('⚠️  Data is still encrypted - decryption happens client-side');
        
        res.json({ 
            success: true, 
            data: sessionData 
        });
        
    } catch (error) {
        console.error('❌ Error retrieving data:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Internal server error' 
        });
    }
});

// GET /api/sessions - List all session IDs
app.get('/api/sessions', async (req, res) => {
    try {
        const allData = await readSessionData();
        const sessionList = Object.keys(allData.sessions).map(sessionId => ({
            sessionId: sessionId,
            startTime: allData.sessions[sessionId].startTime,
            sampleCount: allData.sessions[sessionId].samples.length
        }));
        
        console.log('📋 Returning list of', sessionList.length, 'sessions');
        
        res.json({ 
            success: true, 
            sessions: sessionList 
        });
        
    } catch (error) {
        console.error('❌ Error listing sessions:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Internal server error' 
        });
    }
});

// GET /api/test - Test endpoint
app.get('/api/test', (req, res) => {
    res.json({ 
        success: true, 
        message: 'Server is running',
        timestamp: new Date().toISOString()
    });
});

// ============================================
// HOMOMORPHIC OPERATIONS DEMO ENDPOINT
// ============================================

// POST /api/demo/homomorphic - Demonstrate homomorphic operations
app.post('/api/demo/homomorphic', (req, res) => {
    try {
        const { operation, encryptedValues, publicKey, scalar } = req.body;
        
        let result;
        
        switch (operation) {
            case 'add':
                if (encryptedValues.length < 2) {
                    return res.status(400).json({ error: 'Need at least 2 values for addition' });
                }
                result = homomorphicAdd(encryptedValues[0], encryptedValues[1], publicKey);
                break;
                
            case 'average':
                result = homomorphicAverage(encryptedValues, publicKey, encryptedValues.length);
                break;
                
            case 'multiply':
                if (!scalar) {
                    return res.status(400).json({ error: 'Scalar required for multiplication' });
                }
                result = homomorphicMultiply(encryptedValues[0], scalar, publicKey);
                break;
                
            default:
                return res.status(400).json({ error: 'Invalid operation' });
        }
        
        res.json({ success: true, result: result });
        
    } catch (error) {
        console.error('Homomorphic operation error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================
// ERROR HANDLING
// ============================================

// 404 handler
app.use((req, res) => {
    res.status(404).json({ 
        success: false, 
        error: 'Endpoint not found' 
    });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ 
        success: false, 
        error: 'Internal server error' 
    });
});

// ============================================
// SERVER STARTUP
// ============================================

async function startServer() {
    try {
        // Initialize data storage
        await initializeDataFile();
        
        // Start listening
        app.listen(PORT, () => {
            console.log('\n╔════════════════════════════════════════════════════════╗');
            console.log('║   VR THERAPY SERVER - PRIVACY-PRESERVING BACKEND      ║');
            console.log('╚════════════════════════════════════════════════════════╝');
            console.log('\n✓ Server running on port:', PORT);
            console.log('✓ API endpoints:');
            console.log('  - POST   /api/data');
            console.log('  - GET    /api/data/:sessionId');
            console.log('  - GET    /api/sessions');
            console.log('  - GET    /api/test');
            console.log('  - POST   /api/demo/homomorphic');
            console.log('\n⚠️  IMPORTANT: This server NEVER decrypts data!');
            console.log('   All computations are performed on encrypted values.');
            console.log('   Only authorized clinicians can decrypt using private key.\n');
        });
        
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

// Start the server
startServer();

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('\nShutting down gracefully...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('\nShutting down gracefully...');
    process.exit(0);
});