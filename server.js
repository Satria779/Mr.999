const express = require('express');
const axios = require('axios');
const { URL } = require('url');
const cors = require('cors');
const helmet = require('helmet');

const app = express();
const PORT = 3000;

// Middleware keamanan
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Database sementara untuk log
const scanHistory = [];

// Fungsi AI untuk analisis kerentanan
class AIVulnerabilityScanner {
    constructor() {
        this.threatPatterns = {
            sqlInjection: [
                /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
                /((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i,
                /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i
            ],
            xss: [
                /<script\b[^>]*>([\s\S]*?)<\/script>/gi,
                /javascript:/gi,
                /on\w+\s*=/gi,
                /<\s*iframe/gi,
                /<\s*img[^>]+src\s*=\s*["']?javascript:/gi
            ],
            pathTraversal: [
                /\.\.\//gi,
                /\.\.\\/gi,
                /etc\/passwd/gi,
                /windows\/win\.ini/gi
            ],
            commandInjection: [
                /;\s*\w+/gi,
                /\|\s*\w+/gi,
                /&\s*\w+/gi,
                /`\s*\w+/gi,
                /\$\s*\(/gi
            ]
        };
    }

    async scanWebsite(targetUrl) {
        const results = {
            url: targetUrl,
            timestamp: new Date().toISOString(),
            vulnerabilities: [],
            securityHeaders: {},
            serverInfo: {},
            technologies: [],
            riskScore: 0,
            recommendations: []
        };

        try {
            // 1. Fetch target website
            const response = await axios.get(targetUrl, {
                timeout: 10000,
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Security Scanner)'
                },
                validateStatus: null // Menerima semua status code
            });

            // 2. Analisis headers
            results.securityHeaders = this.analyzeHeaders(response.headers);
            
            // 3. Analisis konten
            results.vulnerabilities = this.analyzeContent(response.data, response.headers);
            
            // 4. Deteksi teknologi
            results.technologies = this.detectTechnologies(response.headers, response.data);
            
            // 5. Analisis server
            results.serverInfo = this.analyzeServer(response.headers, response.status);
            
            // 6. Hitung risk score
            results.riskScore = this.calculateRiskScore(results.vulnerabilities);
            
            // 7. Generate rekomendasi
            results.recommendations = this.generateRecommendations(results);

            return results;

        } catch (error) {
            console.error('Scan error:', error.message);
            
            // Analisis error untuk deteksi
            results.vulnerabilities.push({
                type: 'CONNECTION_ISSUE',
                severity: 'MEDIUM',
                description: `Tidak dapat terhubung ke website: ${error.message}`,
                detection: 'Network analysis'
            });
            
            return results;
        }
    }

    analyzeHeaders(headers) {
        const securityHeaders = {
            'Content-Security-Policy': headers['content-security-policy'] || 'MISSING',
            'X-Frame-Options': headers['x-frame-options'] || 'MISSING',
            'X-Content-Type-Options': headers['x-content-type-options'] || 'MISSING',
            'Strict-Transport-Security': headers['strict-transport-security'] || 'MISSING',
            'X-XSS-Protection': headers['x-xss-protection'] || 'MISSING',
            'Referrer-Policy': headers['referrer-policy'] || 'MISSING',
            'Permissions-Policy': headers['permissions-policy'] || 'MISSING'
        };

        return securityHeaders;
    }

    analyzeContent(content, headers) {
        const vulnerabilities = [];
        const contentStr = content.toString();

        // Deteksi SQL Injection patterns
        this.threatPatterns.sqlInjection.forEach((pattern, index) => {
            if (pattern.test(contentStr)) {
                vulnerabilities.push({
                    type: 'SQL_INJECTION',
                    severity: 'CRITICAL',
                    description: 'Pattern SQL injection terdeteksi dalam respon',
                    detection: `Pattern ${index + 1}`,
                    location: 'Response body'
                });
            }
        });

        // Deteksi XSS
        this.threatPatterns.xss.forEach((pattern, index) => {
            if (pattern.test(contentStr)) {
                vulnerabilities.push({
                    type: 'CROSS_SITE_SCRIPTING',
                    severity: 'HIGH',
                    description: 'Potensi kerentanan XSS terdeteksi',
                    detection: `XSS Pattern ${index + 1}`,
                    location: 'Response body'
                });
            }
        });

        // Cek sensitive data exposure
        const sensitivePatterns = [
            { pattern: /password\s*=\s*["'][^"']*["']/gi, type: 'HARDCODED_PASSWORD' },
            { pattern: /api[_-]?key\s*=\s*["'][^"']*["']/gi, type: 'EXPOSED_API_KEY' },
            { pattern: /token\s*=\s*["'][^"']*["']/gi, type: 'EXPOSED_TOKEN' },
            { pattern: /(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})/g, type: 'CREDIT_CARD_DATA' },
            { pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, type: 'EMAIL_EXPOSURE' }
        ];

        sensitivePatterns.forEach(({ pattern, type }) => {
            const matches = contentStr.match(pattern);
            if (matches && matches.length > 0) {
                vulnerabilities.push({
                    type: type,
                    severity: 'HIGH',
                    description: `Data sensitif ditemukan: ${matches.length} instance`,
                    detection: 'Sensitive data exposure',
                    location: 'Response body',
                    samples: matches.slice(0, 3)
                });
            }
        });

        return vulnerabilities;
    }

    detectTechnologies(headers, content) {
        const technologies = [];
        const contentStr = content.toString();

        // Deteksi dari headers
        const serverHeader = headers['server'] || headers['x-powered-by'];
        if (serverHeader) technologies.push(serverHeader);

        // Deteksi dari content
        const techPatterns = [
            { pattern: /WordPress/i, name: 'WordPress' },
            { pattern: /Joomla/i, name: 'Joomla' },
            { pattern: /Drupal/i, name: 'Drupal' },
            { pattern: /React/i, name: 'React' },
            { pattern: /Vue\.js/i, name: 'Vue.js' },
            { pattern: /jQuery/i, name: 'jQuery' },
            { pattern: /Bootstrap/i, name: 'Bootstrap' },
            { pattern: /nginx/i, name: 'Nginx' },
            { pattern: /Apache/i, name: 'Apache' },
            { pattern: /PHP/i, name: 'PHP' }
        ];

        techPatterns.forEach(({ pattern, name }) => {
            if (pattern.test(contentStr) || pattern.test(JSON.stringify(headers))) {
                technologies.push(name);
            }
        });

        return [...new Set(technologies)];
    }

    analyzeServer(headers, statusCode) {
        return {
            server: headers['server'] || 'Unknown',
            poweredBy: headers['x-powered-by'] || 'Unknown',
            statusCode: statusCode,
            contentType: headers['content-type'] || 'Unknown',
            hasSSL: headers['strict-transport-security'] ? 'Yes' : 'No'
        };
    }

    calculateRiskScore(vulnerabilities) {
        let score = 100;
        
        vulnerabilities.forEach(vuln => {
            switch(vuln.severity) {
                case 'CRITICAL': score -= 40; break;
                case 'HIGH': score -= 25; break;
                case 'MEDIUM': score -= 15; break;
                case 'LOW': score -= 5; break;
            }
        });
        
        return Math.max(0, score);
    }

    generateRecommendations(results) {
        const recommendations = [];
        
        // Rekomendasi berdasarkan headers
        if (results.securityHeaders['Content-Security-Policy'] === 'MISSING') {
            recommendations.push({
                priority: 'HIGH',
                title: 'Tambahkan Content-Security-Policy',
                description: 'CSP membantu mencegah XSS, clickjacking, dan serangan injeksi kode lainnya',
                fix: 'Implementasikan CSP header dengan kebijakan yang ketat'
            });
        }
        
        if (results.securityHeaders['X-Frame-Options'] === 'MISSING') {
            recommendations.push({
                priority: 'MEDIUM',
                title: 'Tambahkan X-Frame-Options',
                description: 'Mencegah clickjacking attacks',
                fix: 'Tambahkan header: X-Frame-Options: DENY atau SAMEORIGIN'
            });
        }
        
        // Rekomendasi berdasarkan vulnerabilities
        results.vulnerabilities.forEach(vuln => {
            if (vuln.type === 'SQL_INJECTION') {
                recommendations.push({
                    priority: 'CRITICAL',
                    title: 'Perbaiki SQL Injection Vulnerability',
                    description: 'Gunakan parameterized queries/prepared statements',
                    fix: 'Ganti query concatenation dengan parameter binding'
                });
            }
            
            if (vuln.type.includes('EXPOSED')) {
                recommendations.push({
                    priority: 'HIGH',
                    title: 'Hapus Data Sensitif dari Source Code',
                    description: 'Data sensitif tidak boleh ada di client-side',
                    fix: 'Gunakan environment variables atau server-side storage'
                });
            }
        });
        
        return recommendations;
    }
}

// Inisialisasi scanner AI
const scanner = new AIVulnerabilityScanner();

// Endpoint untuk scan
app.post('/api/scan', async (req, res) => {
    try {
        const { url } = req.body;
        
        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }

        // Validasi URL
        let parsedUrl;
        try {
            parsedUrl = new URL(url);
            if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
                return res.status(400).json({ error: 'Only HTTP/HTTPS URLs are allowed' });
            }
        } catch (err) {
            return res.status(400).json({ error: 'Invalid URL format' });
        }

        console.log(`Scanning: ${url}`);
        
        // Jalankan scan
        const results = await scanner.scanWebsite(url);
        
        // Simpan ke history
        scanHistory.push({
            url: url,
            timestamp: new Date(),
            riskScore: results.riskScore,
            vulnerabilityCount: results.vulnerabilities.length
        });

        // Keep only last 100 scans
        if (scanHistory.length > 100) {
            scanHistory.shift();
        }

        res.json(results);

    } catch (error) {
        console.error('Server error:', error);
        res.status(500).json({ error: 'Internal server error', details: error.message });
    }
});

// Endpoint untuk history
app.get('/api/history', (req, res) => {
    res.json(scanHistory.slice(-10).reverse());
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
    console.log(`🔒 AI Vulnerability Scanner berjalan di http://localhost:${PORT}`);
    console.log(`⚠️  PERINGATAN: Gunakan hanya untuk website milik Anda sendiri!`);
});