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

                   
