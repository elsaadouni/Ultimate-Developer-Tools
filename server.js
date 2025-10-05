const http = require('http');
const url = require('url');
const { StringDecoder } = require('string_decoder');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');

const PORT = process.env.PORT || 3000;

// Visitor tracking system
const VISITORS_FILE = './visitors.json';

function trackVisitor(type = 'web') {
    try {
        let data = { total: 0, web: 0, api: 0, lastUpdated: new Date().toISOString() };
        
        if (fs.existsSync(VISITORS_FILE)) {
            const fileData = fs.readFileSync(VISITORS_FILE, 'utf8');
            data = JSON.parse(fileData);
        }
        
        data.total++;
        if (data[type] !== undefined) {
            data[type]++;
        } else {
            data[type] = 1;
        }
        data.lastUpdated = new Date().toISOString();
        
        fs.writeFileSync(VISITORS_FILE, JSON.stringify(data, null, 2));
        return data;
    } catch (error) {
        console.error('Visitor tracking error:', error);
        return { total: 0, web: 0, api: 0, lastUpdated: new Date().toISOString() };
    }
}

function getVisitorStats() {
    try {
        if (fs.existsSync(VISITORS_FILE)) {
            const data = fs.readFileSync(VISITORS_FILE, 'utf8');
            return JSON.parse(data);
        }
        return { total: 0, web: 0, api: 0, lastUpdated: new Date().toISOString() };
    } catch (error) {
        console.error('Error reading visitor stats:', error);
        return { total: 0, web: 0, api: 0, lastUpdated: new Date().toISOString() };
    }
}

// Utility functions
function base64Encode(text) {
  return Buffer.from(text).toString('base64');
}

function base64Decode(encoded) {
  try {
    return Buffer.from(encoded, 'base64').toString('utf8');
  } catch (e) {
    throw new Error('Invalid Base64 string');
  }
}

function formatJSON(jsonString) {
  try {
    return JSON.stringify(JSON.parse(jsonString), null, 2);
  } catch (e) {
    throw new Error('Invalid JSON');
  }
}

function minifyJSON(jsonString) {
  try {
    return JSON.stringify(JSON.parse(jsonString));
  } catch (e) {
    throw new Error('Invalid JSON');
  }
}

function xmlToJson(xmlString) {
  try {
    const cleanXml = xmlString.replace(/<\?xml.*?\?>/g, '')
                             .replace(/<!--.*?-->/gs, '')
                             .trim();
    
    return {
      success: true,
      result: { xml: cleanXml },
      converted: new Date().toISOString()
    };
  } catch (e) {
    return {
      success: false,
      error: e.message,
      converted: new Date().toISOString()
    };
  }
}

function minifyXML(xmlString) {
  return xmlString.replace(/>\s+</g, '><').trim();
}

function jsonToXml(jsonString) {
  try {
    const obj = JSON.parse(jsonString);
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += objectToXml(obj, 'root');
    return xml;
  } catch (e) {
    throw new Error('Invalid JSON for XML conversion');
  }
}

function objectToXml(obj, tagName) {
  if (typeof obj === 'string') {
    return `<${tagName}>${escapeXml(obj)}</${tagName}>`;
  }
  
  if (Array.isArray(obj)) {
    return obj.map(item => objectToXml(item, tagName.replace(/s$/, ''))).join('\n');
  }
  
  let xml = '';
  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === 'object' && value !== null) {
      xml += `<${key}>\n${objectToXml(value, key)}</${key}>\n`;
    } else {
      xml += `<${key}>${escapeXml(String(value))}</${key}>\n`;
    }
  }
  
  return xml;
}

function escapeXml(unsafe) {
  return unsafe.replace(/[<>&'"]/g, c => {
    switch (c) {
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '&': return '&amp;';
      case "'": return '&apos;';
      case '"': return '&quot;';
      default: return c;
    }
  });
}

function csvToJson(csvString) {
  const lines = csvString.split('\n').filter(line => line.trim());
  if (lines.length === 0) return [];
  
  const headers = lines[0].split(',').map(h => h.trim().replace(/"/g, ''));
  const result = [];
  
  for (let i = 1; i < lines.length; i++) {
    const values = lines[i].split(',').map(v => v.trim().replace(/"/g, ''));
    const obj = {};
    
    headers.forEach((header, index) => {
      obj[header] = values[index] || '';
    });
    
    result.push(obj);
  }
  
  return result;
}

function csvToXml(csvString) {
  const jsonArray = csvToJson(csvString);
  let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<root>\n';
  
  jsonArray.forEach((item, index) => {
    xml += `  <item id="${index + 1}">\n`;
    Object.entries(item).forEach(([key, value]) => {
      xml += `    <${key}>${escapeXml(String(value))}</${key}>\n`;
    });
    xml += '  </item>\n';
  });
  
  xml += '</root>';
  return xml;
}

function urlEncode(text) {
  return encodeURIComponent(text);
}

function urlDecode(encoded) {
  return decodeURIComponent(encoded);
}

function jwtDecode(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid JWT format');
    
    const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    
    return { header, payload };
  } catch (e) {
    throw new Error('Invalid JWT token');
  }
}

function unixTimestampConverter(timestamp) {
  const date = new Date(timestamp * 1000);
  return {
    iso: date.toISOString(),
    local: date.toString(),
    utc: date.toUTCString()
  };
}

function generatePassword(length = 12, options = {}) {
  const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lowercase = 'abcdefghijklmnopqrstuvwxyz';
  const numbers = '0123456789';
  const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  
  let chars = '';
  if (options.uppercase !== false) chars += uppercase;
  if (options.lowercase !== false) chars += lowercase;
  if (options.numbers !== false) chars += numbers;
  if (options.symbols) chars += symbols;
  
  if (chars === '') chars = uppercase + lowercase + numbers;
  
  let password = '';
  for (let i = 0; i < length; i++) {
    password += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  
  return password;
}

function generateRandomString(length = 32) {
  return crypto.randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length);
}

function calculateHash(text, algorithm) {
  return crypto.createHash(algorithm).update(text).digest('hex');
}

function generateUUID() {
  return uuidv4();
}

function findDifferences(text1, text2) {
  const lines1 = text1.split('\n');
  const lines2 = text2.split('\n');
  const maxLines = Math.max(lines1.length, lines2.length);
  const differences = [];

  for (let i = 0; i < maxLines; i++) {
    const line1 = lines1[i] || '';
    const line2 = lines2[i] || '';
    
    if (line1 !== line2) {
      differences.push({
        line: i + 1,
        left: line1,
        right: line2,
        type: line1 && line2 ? 'modified' : line1 ? 'removed' : 'added'
      });
    }
  }
  
  return differences;
}

// IT Operations Tools
function htmlEscape(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function htmlUnescape(text) {
  return text
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}

function sqlFormatter(sql) {
  return sql
    .replace(/\b(SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TABLE|DATABASE|VALUES|SET|INTO|JOIN|LEFT|RIGHT|INNER|OUTER|ON|AND|OR|NOT|NULL|ORDER BY|GROUP BY|HAVING|LIMIT|OFFSET)\b/gi, '\n$1')
    .replace(/,/g, ',\n    ')
    .trim();
}

function stringLength(text) {
  return {
    characters: text.length,
    bytes: Buffer.byteLength(text, 'utf8'),
    words: text.split(/\s+/).filter(word => word.length > 0).length,
    lines: text.split('\n').length
  };
}

function caseConverter(text, caseType) {
  switch (caseType) {
    case 'upper': return text.toUpperCase();
    case 'lower': return text.toLowerCase();
    case 'title': return text.replace(/\w\S*/g, txt => txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase());
    case 'camel': return text.replace(/(?:^\w|[A-Z]|\b\w)/g, (word, index) => index === 0 ? word.toLowerCase() : word.toUpperCase()).replace(/\s+/g, '');
    case 'snake': return text.toLowerCase().replace(/\s+/g, '_');
    case 'kebab': return text.toLowerCase().replace(/\s+/g, '-');
    default: return text;
  }
}

function loremIpsumGenerator(type = 'paragraphs', count = 1) {
  const words = ['lorem', 'ipsum', 'dolor', 'sit', 'amet', 'consectetur', 'adipiscing', 'elit', 'sed', 'do', 'eiusmod', 'tempor', 'incididunt', 'ut', 'labore', 'et', 'dolore', 'magna', 'aliqua'];
  
  if (type === 'words') {
    return Array.from({ length: count }, () => words[Math.floor(Math.random() * words.length)]).join(' ');
  } else if (type === 'sentences') {
    return Array.from({ length: count }, () => {
      const sentenceLength = Math.floor(Math.random() * 10) + 5;
      const sentenceWords = Array.from({ length: sentenceLength }, () => words[Math.floor(Math.random() * words.length)]);
      return sentenceWords.join(' ') + '.';
    }).join(' ');
  } else {
    return Array.from({ length: count }, () => {
      const paragraphLength = Math.floor(Math.random() * 3) + 2;
      const sentences = Array.from({ length: paragraphLength }, () => {
        const sentenceLength = Math.floor(Math.random() * 10) + 5;
        const sentenceWords = Array.from({ length: sentenceLength }, () => words[Math.floor(Math.random() * words.length)]);
        return sentenceWords.join(' ') + '.';
      });
      return sentences.join(' ');
    }).join('\n\n');
  }
}

function creditCardValidator(number) {
  const cleaned = number.replace(/\D/g, '');
  let sum = 0;
  let shouldDouble = false;
  
  for (let i = cleaned.length - 1; i >= 0; i--) {
    let digit = parseInt(cleaned.charAt(i));
    
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  
  return {
    valid: (sum % 10) === 0,
    type: getCardType(cleaned),
    formatted: formatCardNumber(cleaned)
  };
}

function getCardType(number) {
  const patterns = {
    visa: /^4/,
    mastercard: /^5[1-5]/,
    amex: /^3[47]/,
    discover: /^6(?:011|5)/
  };
  
  for (const [type, pattern] of Object.entries(patterns)) {
    if (pattern.test(number)) return type;
  }
  return 'unknown';
}

function formatCardNumber(number) {
  if (number.length === 16) {
    return number.replace(/(\d{4})/g, '$1 ').trim();
  } else if (number.length === 15) {
    return number.replace(/(\d{4})(\d{6})(\d{5})/, '$1 $2 $3');
  }
  return number;
}

function ipAddressValidator(ip) {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  
  if (ipv4Regex.test(ip)) {
    const parts = ip.split('.');
    const valid = parts.every(part => {
      const num = parseInt(part);
      return num >= 0 && num <= 255;
    });
    return { type: 'IPv4', valid };
  } else if (ipv6Regex.test(ip)) {
    return { type: 'IPv6', valid: true };
  }
  
  return { type: 'unknown', valid: false };
}

function macAddressValidator(mac) {
  const regex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
  return regex.test(mac);
}

function qrCodeGenerator(text) {
  return `https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=${encodeURIComponent(text)}`;
}

function checksumCalculator(text, algorithm) {
  return crypto.createHash(algorithm).update(text).digest('hex');
}

function networkSubnetCalculator(ip, mask) {
  const ipParts = ip.split('.').map(Number);
  const maskParts = mask.split('.').map(Number);
  
  const network = ipParts.map((part, i) => part & maskParts[i]).join('.');
  const broadcast = ipParts.map((part, i) => part | (~maskParts[i] & 255)).join('.');
  
  return {
    network,
    broadcast,
    usableHosts: Math.pow(2, 32 - maskParts.reduce((a, b) => a + Math.log2(256 - b), 0)) - 2
  };
}

// Base64 encoded image for the header
const PROFILE_IMAGE_BASE64 = 'data:image/jpeg;base64,/9j/4AAQSkZJRgABAgEDIAMgAA';

// HTML Template
const HTML_TEMPLATE = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ultimate Developer Tools - elsaadouni.com</title>
    <link rel="icon" href="https://m.elsaadouni.com/assets/img/favicon.ico" type="image/x-icon">
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .railway-bg { background: linear-gradient(135deg, #000000 0%, #1a1a1a 100%); }
        .diff-added { background-color: #10b981; color: white; }
        .diff-removed { background-color: #ef4444; color: white; }
        .diff-modified { background-color: #f59e0b; color: white; }
        .line-number { background: #2d3748; color: #718096; border-right: 1px solid #4a5568; }
        .tool-section { transition: all 0.3s ease; }
        .tool-section:hover { transform: translateY(-2px); }
        .scrollbar-thin::-webkit-scrollbar { width: 6px; }
        .scrollbar-thin::-webkit-scrollbar-track { background: #2d3748; border-radius: 3px; }
        .scrollbar-thin::-webkit-scrollbar-thumb { background: #4a5568; border-radius: 3px; }
        .file-dropzone { border: 2px dashed #4b5563; transition: all 0.3s ease; }
        .file-dropzone.dragover { border-color: #10b981; background-color: #064e3b20; }
        .copy-btn { opacity: 0; transition: opacity 0.3s ease; }
        .hover-container:hover .copy-btn { opacity: 1; }
        .profile-image { width: 40px; height: 40px; border-radius: 50%; object-fit: cover; }
        .truncate-base64 { max-height: 200px; overflow-y: auto; }
        .visitor-counter { 
            background: linear-gradient(135deg, #059669 0%, #0891b2 100%);
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
    </style>
</head>
<body class="railway-bg min-h-screen text-white">
    <!-- Navigation -->
    <nav class="border-b border-gray-800 sticky top-0 z-50 bg-gray-900 bg-opacity-90 backdrop-blur-md">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex justify-between items-center h-16">
                <div class="flex items-center">
                    <img src="${PROFILE_IMAGE_BASE64}" alt="Mohamed Elsaadouni" class="profile-image mr-3">
                    <span class="text-white text-xl font-bold">elsaadouni.com</span>
                </div>
                <div class="flex items-center space-x-4">
                    <div class="visitor-counter px-3 py-1 rounded-full text-sm font-bold hidden md:flex items-center">
                        <i class="fas fa-eye mr-2"></i>
                        <span id="navVisitorCount">Loading...</span>
                    </div>
                    <div class="flex space-x-4 overflow-x-auto">
                        <a href="#base64" class="text-gray-300 hover:text-white transition whitespace-nowrap">Base64</a>
                        <a href="#file-base64" class="text-gray-300 hover:text-white transition whitespace-nowrap">File Base64</a>
                        <a href="#compare" class="text-gray-300 hover:text-white transition whitespace-nowrap">Compare</a>
                        <a href="#convert" class="text-gray-300 hover:text-white transition whitespace-nowrap">Convert</a>
                        <a href="#format" class="text-gray-300 hover:text-white transition whitespace-nowrap">Format</a>
                        <a href="#generators" class="text-gray-300 hover:text-white transition whitespace-nowrap">Generators</a>
                        <a href="#web-tools" class="text-gray-300 hover:text-white transition whitespace-nowrap">Web Tools</a>
                        <a href="#it-tools" class="text-gray-300 hover:text-white transition whitespace-nowrap">IT Tools</a>
                    </div>
                </div>
            </div>
        </div>
    </nav>

    <!-- Hero Section -->
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div class="text-center mb-12">
            <h1 class="text-5xl font-bold mb-6">
                <span class="bg-gradient-to-r from-green-400 to-blue-500 bg-clip-text text-transparent">
                    Ultimate Developer Tools
                </span>
            </h1>
            <p class="text-xl text-gray-300 mb-8 max-w-2xl mx-auto">
                Comprehensive toolkit for developers and IT operations with 30+ essential utilities
            </p>
            
            <!-- Visitor Counter Display -->
            <div class="inline-flex items-center bg-gray-800 px-6 py-4 rounded-2xl mb-8 border border-green-500/30">
                <div class="text-center">
                    <div class="flex items-center justify-center mb-2">
                        <i class="fas fa-users text-green-400 text-2xl mr-3"></i>
                        <div class="text-left">
                            <div class="text-gray-300 text-sm">Total Visitors</div>
                            <div class="text-green-400 font-bold text-3xl" id="heroVisitorCount">Loading...</div>
                        </div>
                    </div>
                    <div class="text-xs text-gray-500">Tracked since deployment</div>
                </div>
            </div>
        </div>

        <!-- Base64 Text Tools Section -->
        <div id="base64" class="tool-section bg-gray-900 rounded-2xl p-6 mb-8 border border-gray-800">
            <div class="flex items-center mb-6">
                <div class="w-12 h-12 bg-green-500 rounded-xl flex items-center justify-center mr-4">
                    <i class="fas fa-code text-white text-xl"></i>
                </div>
                <div>
                    <h2 class="text-2xl font-bold">Base64 Text Tools</h2>
                    <p class="text-gray-400">Encode and decode text with Base64 format</p>
                </div>
            </div>
            
            <div class="grid lg:grid-cols-2 gap-6">
                <div class="space-y-4">
                    <div class="hover-container relative">
                        <label class="block text-sm font-medium text-gray-300 mb-2">Text to Encode/Decode</label>
                        <textarea id="base64Input" placeholder="Enter text to encode or Base64 to decode..." 
                                  class="w-full p-4 bg-gray-800 border border-gray-700 rounded-lg text-white h-32 font-mono text-sm resize-none scrollbar-thin"></textarea>
                        <button onclick="copyText('base64Input')" class="copy-btn absolute top-8 right-2 bg-gray-700 p-2 rounded">
                            <i class="fas fa-copy text-sm"></i>
                        </button>
                    </div>
                    <div class="flex space-x-4">
                        <button onclick="base64EncodeText()" class="flex-1 bg-green-500 text-white p-3 rounded-lg hover:bg-green-600 transition font-semibold">
                            <i class="fas fa-lock mr-2"></i>Encode
                        </button>
                        <button onclick="base64DecodeText()" class="flex-1 bg-blue-500 text-white p-3 rounded-lg hover:bg-blue-600 transition font-semibold">
                            <i class="fas fa-lock-open mr-2"></i>Decode
                        </button>
                        <button onclick="clearField('base64Input')" class="flex-1 bg-gray-600 text-white p-3 rounded-lg hover:bg-gray-500 transition">
                            <i class="fas fa-broom mr-2"></i>Clear
                        </button>
                    </div>
                </div>
                
                <div class="space-y-4">
                    <div class="hover-container relative">
                        <label class="block text-sm font-medium text-gray-300 mb-2">Result</label>
                        <div class="bg-gray-800 rounded-lg p-4 h-32 overflow-auto scrollbar-thin">
                            <pre id="base64Output" class="text-green-400 font-mono text-sm whitespace-pre-wrap break-all"></pre>
                        </div>
                        <button onclick="copyResult('base64Output')" class="copy-btn absolute top-8 right-2 bg-gray-700 p-2 rounded">
                            <i class="fas fa-copy text-sm"></i>
                        </button>
                    </div>
                    <div class="flex space-x-4">
                        <button onclick="copyResult('base64Output')" class="flex-1 bg-gray-700 text-white p-3 rounded-lg hover:bg-gray-600 transition">
                            <i class="fas fa-copy mr-2"></i>Copy
                        </button>
                        <button onclick="clearField('base64Output')" class="flex-1 bg-gray-600 text-white p-3 rounded-lg hover:bg-gray-500 transition">
                            <i class="fas fa-broom mr-2"></i>Clear
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- File Base64 Tools Section -->
        <div id="file-base64" class="tool-section bg-gray-900 rounded-2xl p-6 mb-8 border border-gray-800">
            <div class="flex items-center mb-6">
                <div class="w-12 h-12 bg-purple-500 rounded-xl flex items-center justify-center mr-4">
                    <i class="fas fa-file-code text-white text-xl"></i>
                </div>
                <div>
                    <h2 class="text-2xl font-bold">Base64 File Tools</h2>
                    <p class="text-gray-400">Encode files to Base64 and decode Base64 to downloadable files</p>
                </div>
            </div>
            
            <div class="grid lg:grid-cols-2 gap-8">
                <!-- File to Base64 -->
                <div class="space-y-4">
                    <h3 class="text-lg font-semibold text-gray-300">File to Base64</h3>
                    <div id="fileEncodeDropzone" class="file-dropzone rounded-lg p-8 text-center cursor-pointer">
                        <i class="fas fa-cloud-upload-alt text-4xl text-gray-500 mb-4"></i>
                        <p class="text-gray-400 mb-2">Drag & drop your file here</p>
                        <p class="text-gray-500 text-sm mb-4">or</p>
                        <input type="file" id="fileInput" class="hidden" />
                        <button onclick="document.getElementById('fileInput').click()" 
                                class="bg-purple-500 text-white px-6 py-2 rounded-lg hover:bg-purple-600 transition">
                            Choose File
                        </button>
                        <p class="text-gray-500 text-sm mt-4" id="selectedFileName">No file selected</p>
                    </div>
                    
                    <div class="flex space-x-4">
                        <button onclick="encodeFileToBase64()" class="flex-1 bg-purple-500 text-white p-3 rounded-lg hover:bg-purple-600 transition font-semibold">
                            <i class="fas fa-file-export mr-2"></i>Encode File
                        </button>
                        <button onclick="clearFileEncode()" class="flex-1 bg-gray-600 text-white p-3 rounded-lg hover:bg-gray-500 transition">
                            <i class="fas fa-broom mr-2"></i>Clear
                        </button>
                    </div>
                </div>
                
                <!-- Base64 to File -->
                <div class="space-y-4">
                    <h3 class="text-lg font-semibold text-gray-300">Base64 to File</h3>
                    <div class="hover-container relative">
                        <label class="block text-sm font-medium text-gray-300 mb-2">Base64 String</label>
                        <textarea id="base64FileInput" placeholder="Paste Base64 string here..." 
                                  class="w-full p-4 bg-gray-800 border border-gray-700 rounded-lg text-white h-24 font-mono text-sm resize-none scrollbar-thin"></textarea>
                        <button onclick="copyText('base64FileInput')" class="copy-btn absolute top-8 right-2 bg-gray-700 p-2 rounded">
                            <i class="fas fa-copy text-sm"></i>
                        </button>
                    </div>
                    
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-300 mb-2">File Name</label>
                            <input type="text" id="fileName" placeholder="output" 
                                   class="w-full p-3 bg-gray-800 border border-gray-700 rounded-lg text-white">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-300 mb-2">File Extension</label>
                            <select id="fileExtension" class="w-full p-3 bg-gray-800 border border-gray-700 rounded-lg text-white">
                                <option value="txt">.txt</option>
                                <option value="zip">.zip</option>
                                <option value="csv">.csv</option>
                                <option value="json">.json</option>
                                <option value="xml">.xml</option>
                                <option value="pdf">.pdf</option>
                                <option value="jpg">.jpg</option>
                                <option value="png">.png</option>
                                <option value="bin">.bin</option>
                            </select>
                        </div>
                    </div>
                    
                    <button onclick="decodeBase64ToFile()" class="w-full bg-blue-500 text-white p-3 rounded-lg hover:bg-blue-600 transition font-semibold">
                        <i class="fas fa-file-download mr-2"></i>Decode & Download File
                    </button>
                    
                    <div id="fileOutput" class="hidden mt-4">
                        <div class="bg-yellow-900 border border-yellow-700 rounded-lg p-3 mb-2">
                            <i class="fas fa-info-circle mr-2"></i>
                            <span class="text-yellow-200 text-sm">Large file detected. Content truncated for display.</span>
                        </div>
                        <div class="bg-gray-800 rounded-lg p-4 max-h-64 overflow-auto">
                            <pre id="fileOutputContent" class="text-green-400 font-mono text-sm break-all"></pre>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Add more tool sections here as needed -->

        <!-- Enhanced Footer -->
        <footer class="bg-gray-900 border-t border-gray-800 mt-20">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
                <div class="grid grid-cols-1 md:grid-cols-4 gap-8">
                    
                    <!-- Brand Column -->
                    <div class="col-span-1 md:col-span-2">
                        <div class="flex items-center mb-4">
                            <img src="${PROFILE_IMAGE_BASE64}" alt="Mohamed Elsaadouni" class="profile-image mr-3">
                            <div>
                                <h3 class="text-xl font-bold text-white">Ultimate Developer Tools</h3>
                                <p class="text-green-400 text-sm">by elsaadouni.com</p>
                            </div>
                        </div>
                        <p class="text-gray-400 mb-4 max-w-md">
                            Comprehensive toolkit with 30+ essential utilities for developers, IT professionals, and tech enthusiasts. 
                            Everything you need in one powerful platform.
                        </p>
                        
                        <!-- Stats Row -->
                        <div class="flex flex-wrap gap-6 mb-6">
                            <div class="text-center">
                                <div class="text-2xl font-bold text-green-400" id="footerVisitorCount">0</div>
                                <div class="text-gray-400 text-sm">Total Visitors</div>
                            </div>
                            <div class="text-center">
                                <div class="text-2xl font-bold text-blue-400">30+</div>
                                <div class="text-gray-400 text-sm">Tools</div>
                            </div>
                            <div class="text-center">
                                <div class="text-2xl font-bold text-purple-400">100%</div>
                                <div class="text-gray-400 text-sm">Free</div>
                            </div>
                        </div>

                        <!-- Buy Me a Coffee Section -->
                        <div class="bg-gradient-to-r from-amber-900 to-orange-900 border border-amber-700 rounded-xl p-4 mt-6">
                            <div class="flex items-center justify-between">
                                <div class="flex items-center">
                                    <div class="bg-amber-500 rounded-lg p-2 mr-3">
                                        <i class="fas fa-mug-hot text-white text-xl"></i>
                                    </div>
                                    <div>
                                        <h4 class="text-white font-semibold">Enjoying these tools?</h4>
                                        <p class="text-amber-200 text-sm">Support the development</p>
                                    </div>
                                </div>
                                <a href="https://buymeacoffee.com/elsaadouni" 
                                   target="_blank" 
                                   rel="noopener noreferrer"
                                   class="bg-amber-500 hover:bg-amber-600 text-white px-4 py-2 rounded-lg font-semibold transition-all duration-300 transform hover:scale-105 flex items-center">
                                    <i class="fas fa-coffee mr-2"></i>
                                    Buy me a coffee
                                </a>
                            </div>
                        </div>
                    </div>

                    <!-- Quick Tools Column -->
                    <div class="col-span-1">
                        <h4 class="text-lg font-semibold text-white mb-4">Popular Tools</h4>
                        <ul class="space-y-2">
                            <li><a href="#base64" class="text-gray-400 hover:text-green-400 transition text-sm flex items-center">
                                <i class="fas fa-code mr-2 text-xs"></i>Base64 Encoder/Decoder
                            </a></li>
                            <li><a href="#file-base64" class="text-gray-400 hover:text-green-400 transition text-sm flex items-center">
                                <i class="fas fa-file-code mr-2 text-xs"></i>File Converter
                            </a></li>
                            <li><a href="#generators" class="text-gray-400 hover:text-green-400 transition text-sm flex items-center">
                                <i class="fas fa-key mr-2 text-xs"></i>Password Generator
                            </a></li>
                            <li><a href="#web-tools" class="text-gray-400 hover:text-green-400 transition text-sm flex items-center">
                                <i class="fas fa-globe mr-2 text-xs"></i>JWT Decoder
                            </a></li>
                            <li><a href="#it-tools" class="text-gray-400 hover:text-green-400 transition text-sm flex items-center">
                                <i class="fas fa-server mr-2 text-xs"></i>IT Operations
                            </a></li>
                        </ul>
                    </div>

                    <!-- Connect Column -->
                    <div class="col-span-1">
                        <h4 class="text-lg font-semibold text-white mb-4">Connect & Support</h4>
                        <div class="space-y-3">
                            <a href="https://elsaadouni.com" class="flex items-center text-gray-400 hover:text-green-400 transition text-sm">
                                <i class="fas fa-globe mr-3 text-green-400"></i>
                                Portfolio Website
                            </a>
                            <a href="mailto:contact@elsaadouni.com" class="flex items-center text-gray-400 hover:text-green-400 transition text-sm">
                                <i class="fas fa-envelope mr-3 text-blue-400"></i>
                                Contact Me
                            </a>
                            <a href="https://github.com/elsaadouni" class="flex items-center text-gray-400 hover:text-green-400 transition text-sm">
                                <i class="fab fa-github mr-3 text-purple-400"></i>
                                GitHub
                            </a>
                            <a href="https://linkedin.com/in/elsaadouni" class="flex items-center text-gray-400 hover:text-green-400 transition text-sm">
                                <i class="fab fa-linkedin mr-3 text-blue-500"></i>
                                LinkedIn
                            </a>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Bottom Bar -->
            <div class="border-t border-gray-800">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
                    <div class="flex flex-col md:flex-row justify-between items-center">
                        <div class="text-gray-400 text-sm mb-4 md:mb-0">
                            &copy; 2025 <span class="text-green-400 font-semibold">Ultimate Developer Tools</span>. 
                            All rights reserved. Made with <i class="fas fa-heart text-red-400 mx-1"></i> by 
                            <a href="https://elsaadouni.com" class="text-green-400 hover:underline ml-1">Mohamed Elsaadouni</a>
                        </div>
                    </div>
                </div>
            </div>
        </footer>
    </div>

    <script>
        // Visitor counter functions
        async function loadVisitorCount() {
            try {
                const response = await fetch('/api/visitors/stats');
                const data = await response.json();
                if (data.total !== undefined) {
                    const formattedCount = data.total.toLocaleString();
                    document.getElementById('navVisitorCount').textContent = formattedCount;
                    document.getElementById('heroVisitorCount').textContent = formattedCount;
                    document.getElementById('footerVisitorCount').textContent = formattedCount;
                }
            } catch (error) {
                console.error('Error loading visitor count:', error);
            }
        }

        async function trackPageView() {
            try {
                await fetch('/api/visitors/track', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ type: 'web' })
                });
                loadVisitorCount();
            } catch (error) {
                console.error('Error tracking page view:', error);
            }
        }

        // Your existing JavaScript functions here...
        let currentFile = null;

        function copyText(elementId) {
            const element = document.getElementById(elementId);
            if (!element) {
                showNotification('Element not found', 'error');
                return;
            }

            const text = element.value || element.textContent;
            if (!text || text.trim() === '') {
                showNotification('Nothing to copy!', 'error');
                return;
            }

            copyToClipboard(text);
        }

        function copyResult(elementId) {
            const element = document.getElementById(elementId);
            if (!element) {
                showNotification('Element not found', 'error');
                return;
            }

            const text = element.textContent || element.value;
            if (!text || text.trim() === '') {
                showNotification('Nothing to copy!', 'error');
                return;
            }

            copyToClipboard(text);
        }

        function copyToClipboard(text) {
            const textArea = document.createElement('textarea');
            textArea.value = text;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            textArea.style.top = '-999999px';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            
            try {
                const successful = document.execCommand('copy');
                document.body.removeChild(textArea);
                if (successful) {
                    showNotification('Copied to clipboard!', 'success');
                } else {
                    showNotification('Failed to copy text', 'error');
                }
            } catch (err) {
                document.body.removeChild(textArea);
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(text).then(() => {
                        showNotification('Copied to clipboard!', 'success');
                    }).catch(() => {
                        showNotification('Failed to copy text', 'error');
                    });
                } else {
                    showNotification('Failed to copy text', 'error');
                }
            }
        }

        function clearField(elementId) {
            const element = document.getElementById(elementId);
            if (element) {
                if (element.tagName === 'TEXTAREA' || element.tagName === 'INPUT') {
                    element.value = '';
                } else {
                    element.textContent = '';
                }
                showNotification('Field cleared!', 'success');
            }
        }

        // Base64 Text Functions
        function base64EncodeText() {
            const input = document.getElementById('base64Input').value;
            if (!input) return showNotification('Please enter text to encode', 'error');
            
            try {
                const encoded = btoa(unescape(encodeURIComponent(input)));
                document.getElementById('base64Output').textContent = encoded;
                showNotification('Text encoded successfully!', 'success');
            } catch (error) {
                showNotification('Error: ' + error.message, 'error');
            }
        }

        function base64DecodeText() {
            const input = document.getElementById('base64Input').value;
            if (!input) return showNotification('Please enter Base64 to decode', 'error');
            
            try {
                const decoded = decodeURIComponent(escape(atob(input)));
                document.getElementById('base64Output').textContent = decoded;
                showNotification('Text decoded successfully!', 'success');
            } catch (error) {
                showNotification('Error: Invalid Base64 string', 'error');
            }
        }

        // File Base64 Functions
        function setupFileDropzone() {
            const dropzone = document.getElementById('fileEncodeDropzone');
            const fileInput = document.getElementById('fileInput');
            
            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                dropzone.addEventListener(eventName, preventDefaults, false);
            });
            
            function preventDefaults(e) {
                e.preventDefault();
                e.stopPropagation();
            }
            
            ['dragenter', 'dragover'].forEach(eventName => {
                dropzone.addEventListener(eventName, () => {
                    dropzone.classList.add('dragover');
                }, false);
            });
            
            ['dragleave', 'drop'].forEach(eventName => {
                dropzone.addEventListener(eventName, () => {
                    dropzone.classList.remove('dragover');
                }, false);
            });
            
            dropzone.addEventListener('drop', handleDrop, false);
            fileInput.addEventListener('change', handleFileSelect, false);
        }
        
        function handleDrop(e) {
            const dt = e.dataTransfer;
            const files = dt.files;
            handleFiles(files);
        }
        
        function handleFileSelect(e) {
            const files = e.target.files;
            handleFiles(files);
        }
        
        function handleFiles(files) {
            if (files.length > 0) {
                currentFile = files[0];
                document.getElementById('selectedFileName').textContent = currentFile.name + ' (' + formatFileSize(currentFile.size) + ')';
                showNotification('File selected: ' + currentFile.name, 'success');
            }
        }

        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        function encodeFileToBase64() {
            if (!currentFile) return showNotification('Please select a file first', 'error');
            
            // Show file size warning for large files
            if (currentFile.size > 10 * 1024 * 1024) {
                if (!confirm('This file is large (' + formatFileSize(currentFile.size) + '). Encoding may take a while. Continue?')) {
                    return;
                }
            }
            
            const reader = new FileReader();
            reader.onload = function(e) {
                const base64 = e.target.result.split(',')[1];
                
                // Truncate large files for display
                if (base64.length > 5000) {
                    const truncated = base64.substring(0, 5000) + '... [TRUNCATED - FILE TOO LARGE FOR DISPLAY]';
                    document.getElementById('fileOutputContent').textContent = truncated;
                    document.getElementById('fileOutput').classList.remove('hidden');
                    showNotification('File encoded! Large file truncated for display. Use download for full file.', 'success');
                } else {
                    document.getElementById('fileOutputContent').textContent = base64;
                    document.getElementById('fileOutput').classList.remove('hidden');
                    showNotification('File encoded to Base64 successfully!', 'success');
                }
            };
            reader.onerror = function() {
                showNotification('Error reading file', 'error');
            };
            reader.readAsDataURL(currentFile);
        }
        
        function decodeBase64ToFile() {
            const base64String = document.getElementById('base64FileInput').value.trim();
            if (!base64String) return showNotification('Please enter Base64 string', 'error');
            
            const fileName = document.getElementById('fileName').value || 'output';
            const fileExtension = document.getElementById('fileExtension').value;
            const fullFileName = fileName + '.' + fileExtension;
            
            try {
                const cleanBase64 = base64String.replace(/^data:[^;]+;base64,/, '');
                const binaryString = atob(cleanBase64);
                const bytes = new Uint8Array(binaryString.length);
                for (let i = 0; i < binaryString.length; i++) {
                    bytes[i] = binaryString.charCodeAt(i);
                }
                
                const blob = new Blob([bytes]);
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = fullFileName;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                
                showNotification('File downloaded: ' + fullFileName, 'success');
            } catch (error) {
                showNotification('Error: Invalid Base64 string - ' + error.message, 'error');
            }
        }
        
        function clearFileEncode() {
            currentFile = null;
            document.getElementById('fileInput').value = '';
            document.getElementById('selectedFileName').textContent = 'No file selected';
            document.getElementById('fileOutput').classList.add('hidden');
            document.getElementById('fileOutputContent').textContent = '';
        }

        function showNotification(message, type) {
            const notification = document.createElement('div');
            notification.className = 'fixed top-4 right-4 p-4 rounded-lg border-l-4 z-50 ' +
                (type === 'success' ? 'bg-green-900 border-green-400 text-green-200' : 'bg-red-900 border-red-400 text-red-200');
            notification.innerHTML = 
                '<div class="flex items-center">' +
                '<i class="fas ' + (type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle') + ' mr-2"></i>' +
                '<span>' + message + '</span>' +
                '</div>';
            
            document.body.appendChild(notification);
            
            setTimeout(() => {
                if (document.body.contains(notification)) {
                    document.body.removeChild(notification);
                }
            }, 3000);
        }

        // Smooth scrolling for navigation
        document.querySelectorAll('nav a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            });
        });

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            setupFileDropzone();
            loadVisitorCount();
            trackPageView();
        });
    </script>
</body>
</html>`;

// Create HTTP server
const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const path = parsedUrl.pathname;
  const trimmedPath = path.replace(/^\/+|\/+$/g, '');

  // Track visitor for web requests
  if (req.method === 'GET' && !trimmedPath.startsWith('api/')) {
    trackVisitor('web');
  }

  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  // Health check endpoint
  if (trimmedPath === 'api/health') {
    trackVisitor('api');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'OK',
      message: 'Ultimate Developer Tools API is running by elsaadouni.com',
      timestamp: new Date().toISOString(),
      visitors: getVisitorStats().total
    }));
    return;
  }

  // Visitor stats endpoint
  if (trimmedPath === 'api/visitors/stats' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(getVisitorStats()));
    return;
  }

  // Track visitor endpoint
  if (trimmedPath === 'api/visitors/track' && req.method === 'POST') {
    const decoder = new StringDecoder('utf-8');
    let buffer = '';

    req.on('data', (data) => {
      buffer += decoder.write(data);
    });

    req.on('end', () => {
      buffer += decoder.end();
      try {
        const payload = buffer ? JSON.parse(buffer) : {};
        const type = payload.type || 'web';
        const stats = trackVisitor(type);
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, stats }));
      } catch (error) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON' }));
      }
    });
    return;
  }

  // Handle API endpoints
  if (req.method === 'POST' && trimmedPath.startsWith('api/')) {
    trackVisitor('api');
    const decoder = new StringDecoder('utf-8');
    let buffer = '';

    req.on('data', (data) => {
      buffer += decoder.write(data);
    });

    req.on('end', () => {
      buffer += decoder.end();

      try {
        const payload = buffer ? JSON.parse(buffer) : {};
        let result;

        try {
          switch (trimmedPath) {
            case 'api/base64/encode':
              if (!payload.text) throw new Error('Text is required');
              result = { encoded: base64Encode(payload.text) };
              break;
            case 'api/base64/decode':
              if (!payload.encoded) throw new Error('Encoded string is required');
              result = { decoded: base64Decode(payload.encoded) };
              break;
            case 'api/convert/xml-to-json':
              if (!payload.xml) throw new Error('XML is required');
              result = xmlToJson(payload.xml);
              break;
            case 'api/convert/json-to-xml':
              if (!payload.json) throw new Error('JSON is required');
              result = { xml: jsonToXml(payload.json) };
              break;
            case 'api/convert/csv-to-json':
              if (!payload.csv) throw new Error('CSV is required');
              result = { json: csvToJson(payload.csv) };
              break;
            case 'api/convert/csv-to-xml':
              if (!payload.csv) throw new Error('CSV is required');
              result = { xml: csvToXml(payload.csv) };
              break;
            case 'api/convert/url-encode':
              if (!payload.text) throw new Error('Text is required');
              result = { encoded: urlEncode(payload.text) };
              break;
            case 'api/convert/url-decode':
              if (!payload.encoded) throw new Error('Encoded string is required');
              result = { decoded: urlDecode(payload.encoded) };
              break;
            case 'api/convert/timestamp':
              if (!payload.timestamp) throw new Error('Timestamp is required');
              result = { result: unixTimestampConverter(payload.timestamp) };
              break;
            case 'api/format/json':
              if (!payload.json) throw new Error('JSON is required');
              result = { formatted: formatJSON(payload.json) };
              break;
            case 'api/format/json-minify':
              if (!payload.json) throw new Error('JSON is required');
              result = { formatted: minifyJSON(payload.json) };
              break;
            case 'api/format/xml-minify':
              if (!payload.xml) throw new Error('XML is required');
              result = { formatted: minifyXML(payload.xml) };
              break;
            case 'api/generate/password':
              const length = payload.length || 12;
              const pwdType = payload.type || 'all';
              let options = {};
              if (pwdType === 'alphanumeric') {
                options = { symbols: false };
              } else if (pwdType === 'letters') {
                options = { symbols: false, numbers: false };
              } else if (pwdType === 'numbers') {
                options = { symbols: false, uppercase: false, lowercase: false };
              } else {
                options = { symbols: true };
              }
              result = { password: generatePassword(length, options) };
              break;
            case 'api/generate/hash':
              if (!payload.text || !payload.algorithm) throw new Error('Text and algorithm are required');
              result = { hash: calculateHash(payload.text, payload.algorithm) };
              break;
            case 'api/generate/uuid':
              result = { uuid: generateUUID() };
              break;
            case 'api/generate/random':
              const randomLength = payload.length || 32;
              result = { random: generateRandomString(randomLength) };
              break;
            case 'api/decode/jwt':
              if (!payload.token) throw new Error('JWT token is required');
              result = { decoded: jwtDecode(payload.token) };
              break;
            case 'api/compare/text':
              if (!payload.text1 || !payload.text2) throw new Error('Both texts are required');
              result = { differences: findDifferences(payload.text1, payload.text2) };
              break;
            case 'api/tools/html-escape':
              if (!payload.text) throw new Error('Text is required');
              result = { escaped: htmlEscape(payload.text) };
              break;
            case 'api/tools/html-unescape':
              if (!payload.text) throw new Error('Text is required');
              result = { unescaped: htmlUnescape(payload.text) };
              break;
            case 'api/tools/string-length':
              if (!payload.text) throw new Error('Text is required');
              result = { length: stringLength(payload.text) };
              break;
            case 'api/tools/convert-case':
              if (!payload.text || !payload.caseType) throw new Error('Text and case type are required');
              result = { converted: caseConverter(payload.text, payload.caseType) };
              break;
            case 'api/tools/format-sql':
              if (!payload.sql) throw new Error('SQL is required');
              result = { formatted: sqlFormatter(payload.sql) };
              break;
            case 'api/tools/validate-credit-card':
              if (!payload.number) throw new Error('Credit card number is required');
              result = { validation: creditCardValidator(payload.number) };
              break;
            case 'api/tools/validate-ip':
              if (!payload.ip) throw new Error('IP address is required');
              result = { validation: ipAddressValidator(payload.ip) };
              break;
            case 'api/tools/validate-mac':
              if (!payload.mac) throw new Error('MAC address is required');
              result = { validation: macAddressValidator(payload.mac) };
              break;
            case 'api/tools/lorem-ipsum':
              const loremType = payload.type || 'paragraphs';
              const count = payload.count || 3;
              result = { text: loremIpsumGenerator(loremType, count) };
              break;
            case 'api/tools/checksum':
              if (!payload.text || !payload.algorithm) throw new Error('Text and algorithm are required');
              result = { checksum: checksumCalculator(payload.text, payload.algorithm) };
              break;
            case 'api/tools/qr-code':
              if (!payload.text) throw new Error('Text is required');
              result = { qrCode: qrCodeGenerator(payload.text) };
              break;
            default:
              throw new Error('Endpoint not found');
          }

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        } catch (apiError) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: apiError.message }));
        }
      } catch (parseError) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON payload' }));
      }
    });
    return;
  }

  // Serve the main HTML page for all other routes
  if (req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(HTML_TEMPLATE);
    return;
  }

  // 404 for other methods
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
});

// Start server
server.listen(PORT, () => {
  console.log('🚀 Ultimate Developer Tools running on http://localhost:' + PORT);
  console.log('📍 Health check: http://localhost:' + PORT + '/api/health');
  console.log('👁️  Visitor tracking enabled - stats: http://localhost:' + PORT + '/api/visitors/stats');
  console.log('✅ 30+ tools including: Base64, File converters, Password generators, Hash calculators, IT operations tools and more!');
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down gracefully...');
  server.close(() => {
    console.log('Server closed.');
    process.exit(0);
  });
});
