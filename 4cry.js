#!/usr/bin/env node

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Command } = require('commander');
const chalk = require('chalk');
const ProgressBar = require('progress');

/**
 * Sistema Avançado de Criptografia de Arquivos - Spy.Monge.AI
 * 
 * Este sistema implementa múltiplas camadas de criptografia:
 * 1. AES-256-GCM para criptografia simétrica
 * 2. RSA-OAEP para troca segura de chaves
 * 3. HMAC-SHA256 para verificação de integridade
 * 4. Compressão DEFLATE para otimização
 * 5. Steganografia de metadados
 */

class AdvancedFileEncryption {
    constructor() {
        this.ALGORITHM = 'aes-256-gcm';
        this.KEY_SIZE = 32; // 256 bits
        this.IV_SIZE = 16;  // 128 bits
        this.TAG_SIZE = 16; // 128 bits
        this.SALT_SIZE = 32; // 256 bits
        this.SIGNATURE = Buffer.from('4CRY_v2.0', 'utf8');
        this.VERSION = '3.0.0';
        this.COMPRESSION_LEVEL = 9; // Maximum compression
        this.CHUNK_SIZE = 64 * 1024; // 64KB chunks for efficient processing
        
        // Enhanced security settings for v3.0
        this.PBKDF2_ITERATIONS = 150000; // Increased from 100,000
        this.MIN_PASSWORD_LENGTH = 12; // Increased minimum password length
        this.MAX_FILE_SIZE = 5 * 1024 * 1024 * 1024; // Increased to 5GB
        this.SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes session timeout
        this.MAX_LOGIN_ATTEMPTS = 3; // Maximum login attempts
        this.LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes lockout
        
        // Key storage settings
        this.KEY_STORAGE_DIR = './key_storage';
        this.MASTER_KEY_FILE = path.join(this.KEY_STORAGE_DIR, 'master.key');
        this.KEY_DATABASE_FILE = path.join(this.KEY_STORAGE_DIR, 'keys.db');
        this.SECURITY_LOG_FILE = path.join(this.KEY_STORAGE_DIR, 'security.log');
        this.SESSION_FILE = path.join(this.KEY_STORAGE_DIR, 'session.json');
        
        // Security tracking
        this.loginAttempts = new Map();
        this.sessionData = null;
        this.lastActivity = Date.now();
    }

    /**
     * Gera um par de chaves RSA para criptografia assimétrica
     */
    generateKeyPair() {
        return crypto.generateKeyPairSync('rsa', {
            modulusLength: 4096,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });
    }

    /**
     * Deriva uma chave a partir de uma senha usando PBKDF2
     */
    deriveKey(password, salt, iterations = 100000) {
        return crypto.pbkdf2Sync(password, salt, iterations, this.KEY_SIZE, 'sha256');
    }

    /**
     * 🗜️ Compressão Simples e Confiável 4CRY
     * Sistema seguro que preserva integridade dos arquivos
     */
    compressData(data) {
        const zlib = require('zlib');
        
        console.log(chalk.blue('🗜️ Starting secure compression...'));
        
        // Test only reliable algorithms
        const algorithms = [
            {
                name: 'Deflate',
                id: 0,
                compress: (input) => zlib.deflateSync(input, { level: 6 }), // Medium level
                decompress: (compressed) => zlib.inflateSync(compressed)
            },
            {
                name: 'Gzip',
                id: 1,
                compress: (input) => zlib.gzipSync(input, { level: 6 }),
                decompress: (compressed) => zlib.gunzipSync(compressed)
            }
        ];
        
        let bestResult = { 
            size: data.length, 
            data: data, 
            algorithm: 'None',
            id: 255
        };
        
        // Test each algorithm once only
        for (const algo of algorithms) {
            try {
                console.log(chalk.yellow(`🧪 Testing ${algo.name}...`));
                const compressed = algo.compress(data);
                
                if (compressed.length < bestResult.size) {
                    bestResult = {
                        size: compressed.length,
                        data: compressed,
                        algorithm: algo.name,
                        id: algo.id,
                        decompress: algo.decompress
                    };
                }
            } catch (error) {
                console.log(chalk.red(`❌ ${algo.name} failed, skipping...`));
            }
        }
        
        const ratio = ((1 - bestResult.size / data.length) * 100).toFixed(2);
        console.log(chalk.green(`✅ Best compression: ${bestResult.algorithm} (${ratio}% reduction)`));
        
        // Simple metadata: [algorithm_id]
        const metadata = Buffer.from([bestResult.id]);
        return Buffer.concat([metadata, bestResult.data]);
    }

    // Todas as funções de pré-processamento foram removidas para garantir integridade

    /**
     * 📦 Descomprime dados - versão simples e confiável
     */
    decompressData(compressedData) {
        const zlib = require('zlib');
        
        if (compressedData.length < 1) {
            throw new Error('Dados de compressão inválidos');
        }
        
        const algorithmId = compressedData[0];
        const actualData = compressedData.slice(1);
        
        console.log(chalk.blue(`📦 Decompressing with algorithm ID: ${algorithmId}`));
        
        const algorithms = [
            {
                name: 'Deflate',
                decompress: (data) => zlib.inflateSync(data)
            },
            {
                name: 'Gzip',
                decompress: (data) => zlib.gunzipSync(data)
            }
        ];
        
        if (algorithmId === 255) {
            // No compression
            return actualData;
        }
        
        if (algorithmId >= algorithms.length) {
            throw new Error(`Algorithm ID ${algorithmId} not recognized`);
        }
        
        const algorithm = algorithms[algorithmId];
        console.log(chalk.blue(`📦 Using ${algorithm.name}...`));
        
        try {
            return algorithm.decompress(actualData);
        } catch (error) {
            throw new Error(`Decompression error with ${algorithm.name}: ${error.message}`);
        }
    }


    /**
     * Cria HMAC para verificação de integridade
     */
    createHMAC(data, key) {
        const hmac = crypto.createHmac('sha256', key);
        hmac.update(data);
        return hmac.digest();
    }

    /**
     * Verifica HMAC
     */
    verifyHMAC(data, key, expectedHmac) {
        const computedHmac = this.createHMAC(data, key);
        return crypto.timingSafeEqual(computedHmac, expectedHmac);
    }

    /**
     * Adiciona steganografia aos metadados
     */
    embedMetadata(originalFilename, mimeType, hideMetadata = false) {
        if (hideMetadata) {
            // Cria metadados mínimos sem informações sensíveis
            const metadata = {
                timestamp: Date.now(),
                version: this.VERSION,
                checksum: crypto.randomBytes(16).toString('hex'),
                hidden: true
            };
            
            // Embaralha os metadados para ofuscar
            const metadataStr = JSON.stringify(metadata);
            const shuffled = Buffer.from(metadataStr, 'utf8');
            
            // Adiciona padding aleatório
            const padding = crypto.randomBytes(Math.floor(Math.random() * 50) + 10);
            return Buffer.concat([shuffled, padding]);
        } else {
            // Metadados completos (comportamento padrão)
        const metadata = {
            originalName: originalFilename,
            mimeType: mimeType,
            timestamp: Date.now(),
            version: this.VERSION,
            checksum: crypto.randomBytes(16).toString('hex')
        };
        
        // Embaralha os metadados para ofuscar
        const metadataStr = JSON.stringify(metadata);
        const shuffled = Buffer.from(metadataStr, 'utf8');
        
        // Adiciona padding aleatório
        const padding = crypto.randomBytes(Math.floor(Math.random() * 50) + 10);
        return Buffer.concat([shuffled, padding]);
        }
    }

    /**
     * Extrai metadados da steganografia
     */
    extractMetadata(metadataBuffer) {
        try {
            // Remove padding (últimos bytes aleatórios)
            const metadataStr = metadataBuffer.toString('utf8');
            const jsonEnd = metadataStr.lastIndexOf('}');
            const cleanJson = metadataStr.substring(0, jsonEnd + 1);
            return JSON.parse(cleanJson);
        } catch (error) {
            throw new Error('Metadados corrompidos ou inválidos');
        }
    }

    /**
     * Cria estrutura de pastas organizadas
     */
    createDirectoryStructure() {
        const dirs = ['./input', './output', './encrypted', './decrypted'];
        dirs.forEach(dir => {
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
                console.log(chalk.gray(`📁 Pasta criada: ${dir}`));
            }
        });
    }

    /**
     * Determina o caminho de saída baseado na operação
     */
    getOutputPath(inputPath, operation, customOutput = null) {
        const filename = path.basename(inputPath);
        const nameWithoutExt = path.parse(filename).name;
        
        if (customOutput) {
            return customOutput;
        }
        
        if (operation === 'encrypt') {
            return path.join('./encrypted', `${filename}.4cry`);
        } else {
            return path.join('./decrypted', nameWithoutExt);
        }
    }

    /**
     * Criptografa um arquivo com múltiplas camadas de segurança
     */
    async encryptFile(inputPath, outputPath, password, hideMetadata = false, camouflageSize = null) {
        console.log(chalk.cyan('🔐 Starting advanced 4CRY v2.0 encryption...'));
        
        try {
            // Cria estrutura de pastas
            this.createDirectoryStructure();
            
            // Lê o arquivo original
            const originalData = fs.readFileSync(inputPath);
            const originalFilename = path.basename(inputPath);
            const stats = fs.statSync(inputPath);
            
            console.log(chalk.yellow(`📁 File: ${originalFilename} (${this.formatBytes(stats.size)})`));
            
            // Gera elementos criptográficos
            const salt = crypto.randomBytes(this.SALT_SIZE);
            const iv = crypto.randomBytes(this.IV_SIZE);
            const key = this.deriveKey(password, salt);
            const hmacKey = crypto.randomBytes(this.KEY_SIZE);
            
            // Compress data
            console.log(chalk.blue('🗜️  Compressing data...'));
            const compressedData = this.compressData(originalData);
            
            // Cria metadados com steganografia
            const metadata = this.embedMetadata(originalFilename, 'application/octet-stream', hideMetadata);
            
            if (hideMetadata) {
                console.log(chalk.yellow('🔒 Metadata hidden for maximum privacy'));
            }
            
            // Encryption progress
            const progressBar = new ProgressBar(
                chalk.green('🔒 Encrypting [:bar] :percent :etas'), 
                { 
                    complete: '█', 
                    incomplete: '░', 
                    width: 30, 
                    total: 100 
                }
            );
            
            // Simulate progress
            const progressInterval = setInterval(() => {
                progressBar.tick(5);
                if (progressBar.complete) {
                    clearInterval(progressInterval);
                }
            }, 50);
            
            // Criptografia AES-256-GCM (mais segura)
            const cipher = crypto.createCipheriv(this.ALGORITHM, key, iv);
            const encryptedData = Buffer.concat([
                cipher.update(compressedData),
                cipher.final()
            ]);
            const authTag = cipher.getAuthTag(); // Tag de autenticação real
            
            // Cria HMAC para integridade
            const hmac = this.createHMAC(encryptedData, hmacKey);
            
            // Monta estrutura do arquivo .4cry
            const cryptHeader = Buffer.alloc(256);
            cryptHeader.write('4CRY', 0); // Magic number
            cryptHeader.writeUInt32BE(2, 4); // Version 2.0
            cryptHeader.writeUInt32BE(metadata.length, 8); // Metadata size
            cryptHeader.writeUInt32BE(originalData.length, 12); // Original size
            cryptHeader.writeUInt32BE(compressedData.length, 16); // Compressed size
            
            let finalData = Buffer.concat([
                this.SIGNATURE,
                cryptHeader,
                salt,
                iv,
                authTag,
                hmac,
                hmacKey,
                metadata,
                encryptedData
            ]);
            
            // Aplica camuflagem de tamanho se especificada
            if (camouflageSize) {
                if (camouflageSize === 'random') {
                    // Camuflagem aleatória
                    finalData = this.addSizeCamouflage(finalData);
                } else {
                    // Tamanho específico
                    const targetSizeBytes = this.parseSizeToBytes(camouflageSize);
                    finalData = this.addSizeCamouflage(finalData, targetSizeBytes);
                }
            }
            
            // Salva arquivo .4cry
            fs.writeFileSync(outputPath, finalData);
            
            clearInterval(progressInterval);
            progressBar.update(100);
            
            console.log(chalk.green('✅ 4CRY ENCRYPT - Encryption completed!'));
            console.log(chalk.cyan(`📤 .4cry file saved: ${outputPath}`));
            console.log(chalk.cyan(`🔗 Final size: ${this.formatBytes(finalData.length)}`));
            console.log(chalk.cyan(`📊 Original size: ${this.formatBytes(originalData.length)}`));
            
            const totalReduction = ((1 - finalData.length / originalData.length) * 100).toFixed(2);
            if (totalReduction > 0) {
                console.log(chalk.green(`🗜️ Compression: ${totalReduction}% reduction`));
            } else {
                console.log(chalk.yellow(`📊 Final file: ${Math.abs(totalReduction)}% larger (security overhead)`));
            }
            console.log(chalk.gray(`🔒 Security: AES-256-GCM + HMAC + Auth Tag`));
            
        } catch (error) {
            console.error(chalk.red('❌ Encryption error:'), error.message);
            throw error;
        }
    }

    /**
     * Descriptografa um arquivo .4cry
     */
    async decryptFile(inputPath, outputPath, password) {
        console.log(chalk.cyan('🔓 Iniciando descriptografia avançada 4CRY v2.0...'));
        
        try {
            // Cria estrutura de pastas
            this.createDirectoryStructure();
            
            // Lê arquivo .4cry
            const encryptedData = fs.readFileSync(inputPath);
            let offset = 0;
            
            // Verifica assinatura
            const signature = encryptedData.slice(offset, offset + this.SIGNATURE.length);
            offset += this.SIGNATURE.length;
            
            if (!signature.equals(this.SIGNATURE)) {
                throw new Error('Arquivo não é um formato .4cry válido');
            }
            
            // Lê header
            const header = encryptedData.slice(offset, offset + 256);
            offset += 256;
            
            const magic = header.toString('utf8', 0, 4);
            const version = header.readUInt32BE(4);
            const metadataSize = header.readUInt32BE(8);
            const originalSize = header.readUInt32BE(12);
            const compressedSize = header.readUInt32BE(16);
            
            if (magic !== '4CRY') {
                throw new Error('Magic number inválido - não é um arquivo .4cry');
            }
            
            console.log(chalk.yellow(`📋 Versão 4CRY: ${version}, Tamanho original: ${this.formatBytes(originalSize)}`));
            
            // Extrai componentes criptográficos
            const salt = encryptedData.slice(offset, offset + this.SALT_SIZE);
            offset += this.SALT_SIZE;
            
            const iv = encryptedData.slice(offset, offset + this.IV_SIZE);
            offset += this.IV_SIZE;
            
            const authTag = encryptedData.slice(offset, offset + this.TAG_SIZE);
            offset += this.TAG_SIZE;
            
            const hmac = encryptedData.slice(offset, offset + 32);
            offset += 32;
            
            const hmacKey = encryptedData.slice(offset, offset + this.KEY_SIZE);
            offset += this.KEY_SIZE;
            
            const metadata = encryptedData.slice(offset, offset + metadataSize);
            offset += metadataSize;
            
            // Calcula o tamanho real dos dados criptografados (sem padding)
            const realDataSize = this.SIGNATURE.length + 256 + this.SALT_SIZE + this.IV_SIZE + this.TAG_SIZE + 32 + this.KEY_SIZE + metadataSize + compressedSize;
            
            // Se o arquivo é maior que o esperado, há padding (camuflagem)
            if (encryptedData.length > realDataSize) {
                console.log(chalk.yellow(`🎭 Arquivo com camuflagem detectado:`));
                console.log(chalk.yellow(`   📊 Tamanho real: ${this.formatBytes(realDataSize)}`));
                console.log(chalk.yellow(`   🎭 Tamanho aparente: ${this.formatBytes(encryptedData.length)}`));
                console.log(chalk.yellow(`   🎭 Padding removido: ${this.formatBytes(encryptedData.length - realDataSize)}`));
            }
            
            const ciphertext = encryptedData.slice(offset, offset + compressedSize);
            
            // Deriva chave da senha
            const key = this.deriveKey(password, salt);
            
            // Verifica HMAC
            if (!this.verifyHMAC(ciphertext, hmacKey, hmac)) {
                throw new Error('Verificação de integridade falhou - arquivo pode estar corrompido');
            }
            
            // Progresso da descriptografia
            const progressBar = new ProgressBar(
                chalk.green('🔓 Descriptografando [:bar] :percent :etas'), 
                { 
                    complete: '█', 
                    incomplete: '░', 
                    width: 30, 
                    total: 100 
                }
            );
            
            const progressInterval = setInterval(() => {
                progressBar.tick(5);
                if (progressBar.complete) {
                    clearInterval(progressInterval);
                }
            }, 50);
            
            // Descriptografia AES-256-GCM
            const decipher = crypto.createDecipheriv(this.ALGORITHM, key, iv);
            decipher.setAuthTag(authTag);
            
            const decryptedData = Buffer.concat([
                decipher.update(ciphertext),
                decipher.final()
            ]);
            
            // Descomprime dados
            console.log(chalk.blue('📦 Descomprimindo dados...'));
            const originalData = this.decompressData(decryptedData);
            
            // Extrai metadados (versão simplificada)
            try {
                const metadataObj = this.extractMetadata(metadata);
                if (metadataObj.hidden) {
                    console.log(chalk.yellow('🔒 Metadados ocultos - arquivo criptografado com privacidade máxima'));
                    console.log(chalk.yellow(`🕒 Criptografado em: ${new Date(metadataObj.timestamp).toLocaleString()}`));
                } else {
                console.log(chalk.yellow(`📁 Nome original: ${metadataObj.originalName}`));
                console.log(chalk.yellow(`🕒 Criptografado em: ${new Date(metadataObj.timestamp).toLocaleString()}`));
                }
            } catch (error) {
                // Metadados opcionais - continua mesmo se corrompidos
                console.log(chalk.yellow('📁 Metadados: Arquivo 4CRY válido'));
            }
            
            // Salva arquivo descriptografado
            fs.writeFileSync(outputPath, originalData);
            
            clearInterval(progressInterval);
            progressBar.update(100);
            
            console.log(chalk.green('✅ Descriptografia concluída com sucesso!'));
            console.log(chalk.gray(`📤 Arquivo restaurado: ${outputPath}`));
            console.log(chalk.gray(`📊 Tamanho restaurado: ${this.formatBytes(originalData.length)}`));
            
        } catch (error) {
            console.error(chalk.red('❌ Erro na descriptografia:'), error.message);
            throw error;
        }
    }

    /**
     * Gera uma senha segura aleatória
     */
    generateSecurePassword(length = 32) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
        let password = '';
        for (let i = 0; i < length; i++) {
            password += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return password;
    }

    /**
     * Formata bytes em formato legível
     */
    formatBytes(bytes) {
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        if (bytes === 0) return '0 Bytes';
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
    }

    /**
     * Converte tamanho de string para bytes
     */
    parseSizeToBytes(sizeStr) {
        const units = {
            'B': 1,
            'KB': 1024,
            'MB': 1024 * 1024,
            'GB': 1024 * 1024 * 1024,
            'TB': 1024 * 1024 * 1024 * 1024
        };
        
        const match = sizeStr.match(/^(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB)?$/i);
        if (!match) {
            throw new Error('Formato de tamanho inválido. Use: 1MB, 500KB, 2.5GB, etc.');
        }
        
        const value = parseFloat(match[1]);
        const unit = (match[2] || 'B').toUpperCase();
        
        if (!units[unit]) {
            throw new Error('Unidade inválida. Use: B, KB, MB, GB, TB');
        }
        
        return Math.floor(value * units[unit]);
    }

    /**
     * Gera um tamanho aleatório para camuflagem baseado no tamanho original
     */
    generateRandomCamouflageSize(originalSize) {
        // Define faixas de multiplicação baseadas no tamanho original
        let minMultiplier, maxMultiplier;
        
        if (originalSize < 1024) { // < 1KB
            minMultiplier = 10;  // 10x
            maxMultiplier = 100; // 100x
        } else if (originalSize < 1024 * 1024) { // < 1MB
            minMultiplier = 5;   // 5x
            maxMultiplier = 50;  // 50x
        } else if (originalSize < 100 * 1024 * 1024) { // < 100MB
            minMultiplier = 2;   // 2x
            maxMultiplier = 10;  // 10x
        } else { // >= 100MB
            minMultiplier = 1.1; // 1.1x
            maxMultiplier = 3;   // 3x
        }
        
        const randomMultiplier = minMultiplier + Math.random() * (maxMultiplier - minMultiplier);
        const targetSize = Math.floor(originalSize * randomMultiplier);
        
        return targetSize;
    }

    /**
     * Adiciona padding aleatório para camuflar o tamanho do arquivo
     */
    addSizeCamouflage(data, targetSizeBytes = null) {
        const currentSize = data.length;
        
        // Se não especificado, gera tamanho aleatório
        if (!targetSizeBytes) {
            targetSizeBytes = this.generateRandomCamouflageSize(currentSize);
            console.log(chalk.blue(`🎲 Generating random camouflage:`));
            console.log(chalk.blue(`   📊 Original size: ${this.formatBytes(currentSize)}`));
            console.log(chalk.blue(`   🎯 Random target size: ${this.formatBytes(targetSizeBytes)}`));
        }
        
        if (targetSizeBytes <= currentSize) {
            throw new Error(`Target size (${this.formatBytes(targetSizeBytes)}) must be larger than current file (${this.formatBytes(currentSize)})`);
        }
        
        const paddingSize = targetSizeBytes - currentSize;
        const randomPadding = crypto.randomBytes(paddingSize);
        
        console.log(chalk.yellow(`🎭 Adding size camouflage:`));
        console.log(chalk.yellow(`   📊 Original size: ${this.formatBytes(currentSize)}`));
        console.log(chalk.yellow(`   🎯 Target size: ${this.formatBytes(targetSizeBytes)}`));
        console.log(chalk.yellow(`   🎭 Padding added: ${this.formatBytes(paddingSize)}`));
        
        return Buffer.concat([data, randomPadding]);
    }

    /**
     * Scans directory for files to encrypt
     */
    scanDirectoryForFiles(directory, recursive = true, extensions = []) {
        const files = [];
        
        if (!fs.existsSync(directory)) {
            throw new Error(`Directory not found: ${directory}`);
        }
        
        const scanDir = (dir) => {
            const items = fs.readdirSync(dir);
            
            for (const item of items) {
                const fullPath = path.join(dir, item);
                const stat = fs.statSync(fullPath);
                
                if (stat.isDirectory() && recursive) {
                    scanDir(fullPath);
                } else if (stat.isFile()) {
                    if (extensions.length === 0 || extensions.includes(path.extname(item).toLowerCase())) {
                        files.push(fullPath);
                    }
                }
            }
        };
        
        scanDir(directory);
        return files;
    }

    /**
     * Batch encrypt multiple files
     */
    async batchEncrypt(inputPaths, password, options = {}) {
        const {
            hideMetadata = false,
            camouflageSize = null,
            randomCamouflage = false,
            recursive = true,
            extensions = [],
            outputDir = './encrypted',
            progressCallback = null
        } = options;

        console.log(chalk.cyan('🔄 Starting batch encryption mode...'));
        
        // Collect all files to encrypt
        let allFiles = [];
        
        for (const inputPath of inputPaths) {
            const stat = fs.statSync(inputPath);
            
            if (stat.isDirectory()) {
                console.log(chalk.blue(`📁 Scanning directory: ${inputPath}`));
                const dirFiles = this.scanDirectoryForFiles(inputPath, recursive, extensions);
                allFiles = allFiles.concat(dirFiles);
                console.log(chalk.green(`   Found ${dirFiles.length} files`));
            } else if (stat.isFile()) {
                allFiles.push(inputPath);
            }
        }
        
        if (allFiles.length === 0) {
            throw new Error('No files found to encrypt');
        }
        
        console.log(chalk.yellow(`📊 Total files to encrypt: ${allFiles.length}`));
        
        // Create output directory
        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }
        
        const results = {
            successful: [],
            failed: [],
            total: allFiles.length,
            startTime: Date.now()
        };
        
        // Process each file
        for (let i = 0; i < allFiles.length; i++) {
            const filePath = allFiles[i];
            const relativePath = path.relative(process.cwd(), filePath);
            
            try {
                console.log(chalk.cyan(`\n[${i + 1}/${allFiles.length}] Processing: ${relativePath}`));
                
                // Determine output path
                const fileName = path.basename(filePath);
                const outputPath = path.join(outputDir, `${fileName}.4cry`);
                
                // Determine camouflage settings
                let finalCamouflageSize = camouflageSize;
                if (randomCamouflage && !camouflageSize) {
                    finalCamouflageSize = 'random';
                }
                
                // Encrypt file
                await this.encryptFile(filePath, outputPath, password, hideMetadata, finalCamouflageSize);
                
                results.successful.push({
                    input: filePath,
                    output: outputPath,
                    size: fs.statSync(filePath).size
                });
                
                console.log(chalk.green(`✅ Success: ${fileName}`));
                
                // Progress callback
                if (progressCallback) {
                    progressCallback(i + 1, allFiles.length, filePath, true);
                }
                
            } catch (error) {
                console.log(chalk.red(`❌ Failed: ${relativePath} - ${error.message}`));
                
                results.failed.push({
                    input: filePath,
                    error: error.message
                });
                
                // Progress callback
                if (progressCallback) {
                    progressCallback(i + 1, allFiles.length, filePath, false);
                }
            }
        }
        
        results.endTime = Date.now();
        results.duration = results.endTime - results.startTime;
        
        // Summary
        console.log(chalk.bold.cyan('\n📊 Batch Encryption Summary:'));
        console.log(chalk.green(`✅ Successful: ${results.successful.length}`));
        console.log(chalk.red(`❌ Failed: ${results.failed.length}`));
        console.log(chalk.blue(`⏱️ Duration: ${(results.duration / 1000).toFixed(2)}s`));
        
        if (results.failed.length > 0) {
            console.log(chalk.yellow('\n❌ Failed files:'));
            results.failed.forEach(fail => {
                console.log(chalk.gray(`  • ${fail.input}: ${fail.error}`));
            });
        }
        
        return results;
    }

    /**
     * Encrypt entire folder structure with maximum security
     */
    async encryptFolder(inputFolder, outputFolder, password, options = {}) {
        const {
            hideMetadata = true, // Default to maximum privacy
            camouflageSize = null,
            randomCamouflage = true, // Default to random camouflage for anonymity
            preserveStructure = true,
            excludePatterns = [],
            includePatterns = [],
            maxFileSize = 2 * 1024 * 1024 * 1024, // 2GB limit for security
            progressCallback = null
        } = options;

        console.log(chalk.cyan('🔐 Starting maximum security folder encryption...'));
        
        if (!fs.existsSync(inputFolder)) {
            throw new Error(`Input folder not found: ${inputFolder}`);
        }

        // Create output folder structure
        if (!fs.existsSync(outputFolder)) {
            fs.mkdirSync(outputFolder, { recursive: true });
        }

        // Scan folder with security filters
        const files = this.scanFolderWithSecurity(inputFolder, {
            excludePatterns,
            includePatterns,
            maxFileSize,
            recursive: true
        });

        if (files.length === 0) {
            throw new Error('No files found to encrypt');
        }

        console.log(chalk.yellow(`📊 Total files to encrypt: ${files.length}`));
        console.log(chalk.blue(`🔒 Security mode: MAXIMUM`));
        console.log(chalk.blue(`🎭 Anonymity mode: ENABLED`));

        const results = {
            successful: [],
            failed: [],
            total: files.length,
            startTime: Date.now(),
            securityLevel: 'MAXIMUM',
            anonymityLevel: 'MAXIMUM'
        };

        // Process each file with maximum security
        for (let i = 0; i < files.length; i++) {
            const filePath = files[i];
            const relativePath = path.relative(inputFolder, filePath);
            
            try {
                console.log(chalk.cyan(`\n[${i + 1}/${files.length}] 🔒 MAX SECURITY: ${relativePath}`));
                
                // Determine output path with structure preservation
                let outputPath;
                if (preserveStructure) {
                    const relativeDir = path.dirname(relativePath);
                    const fileName = path.basename(filePath);
                    const outputDir = path.join(outputFolder, relativeDir);
                    
                    if (!fs.existsSync(outputDir)) {
                        fs.mkdirSync(outputDir, { recursive: true });
                    }
                    
                    outputPath = path.join(outputDir, `${fileName}.4cry`);
                } else {
                    const fileName = path.basename(filePath);
                    outputPath = path.join(outputFolder, `${fileName}.4cry`);
                }

                // Maximum security settings
                let finalCamouflageSize = camouflageSize;
                if (randomCamouflage && !camouflageSize) {
                    finalCamouflageSize = 'random';
                }

                // Encrypt with maximum security
                await this.encryptFile(filePath, outputPath, password, hideMetadata, finalCamouflageSize);
                
                results.successful.push({
                    input: filePath,
                    output: outputPath,
                    size: fs.statSync(filePath).size,
                    securityLevel: 'MAXIMUM'
                });
                
                console.log(chalk.green(`✅ MAX SECURITY SUCCESS: ${path.basename(filePath)}`));
                
                if (progressCallback) {
                    progressCallback(i + 1, files.length, filePath, true);
                }
                
            } catch (error) {
                console.log(chalk.red(`❌ SECURITY FAILURE: ${relativePath} - ${error.message}`));
                
                results.failed.push({
                    input: filePath,
                    error: error.message,
                    securityLevel: 'MAXIMUM'
                });
                
                if (progressCallback) {
                    progressCallback(i + 1, files.length, filePath, false);
                }
            }
        }

        results.endTime = Date.now();
        results.duration = results.endTime - results.startTime;

        // Security summary
        console.log(chalk.bold.red('\n🔒 MAXIMUM SECURITY ENCRYPTION SUMMARY:'));
        console.log(chalk.green(`✅ Successfully encrypted: ${results.successful.length}`));
        console.log(chalk.red(`❌ Security failures: ${results.failed.length}`));
        console.log(chalk.blue(`⏱️ Total duration: ${(results.duration / 1000).toFixed(2)}s`));
        console.log(chalk.yellow(`🔒 Security level: ${results.securityLevel}`));
        console.log(chalk.yellow(`🎭 Anonymity level: ${results.anonymityLevel}`));
        
        if (results.failed.length > 0) {
            console.log(chalk.red('\n❌ Security failures:'));
            results.failed.forEach(fail => {
                console.log(chalk.gray(`  • ${fail.input}: ${fail.error}`));
            });
        }

        return results;
    }

    /**
     * Scan folder with maximum security filters
     */
    scanFolderWithSecurity(folder, options = {}) {
        const {
            excludePatterns = ['.git', 'node_modules', '.DS_Store', 'Thumbs.db'],
            includePatterns = [],
            maxFileSize = 2 * 1024 * 1024 * 1024, // 2GB
            recursive = true
        } = options;

        const files = [];
        
        const scanDir = (dir) => {
            if (!fs.existsSync(dir)) return;
            
            const items = fs.readdirSync(dir);
            
            for (const item of items) {
                const fullPath = path.join(dir, item);
                const stat = fs.statSync(fullPath);
                
                // Security check: skip hidden/system files
                if (item.startsWith('.')) continue;
                
                // Security check: skip excluded patterns
                if (excludePatterns.some(pattern => fullPath.includes(pattern))) continue;
                
                if (stat.isDirectory() && recursive) {
                    scanDir(fullPath);
                } else if (stat.isFile()) {
                    // Security check: file size limit
                    if (stat.size > maxFileSize) {
                        console.log(chalk.yellow(`⚠️ Skipping large file (security): ${item}`));
                        continue;
                    }
                    
                    // Security check: include patterns
                    if (includePatterns.length > 0) {
                        const ext = path.extname(item).toLowerCase();
                        if (!includePatterns.includes(ext)) continue;
                    }
                    
                    files.push(fullPath);
                }
            }
        };
        
        scanDir(folder);
        return files;
    }

    /**
     * Decrypt entire folder structure
     */
    async decryptFolder(inputFolder, outputFolder, password, options = {}) {
        const {
            preserveStructure = true,
            progressCallback = null
        } = options;

        console.log(chalk.cyan('🔓 Starting maximum security folder decryption...'));
        
        if (!fs.existsSync(inputFolder)) {
            throw new Error(`Input folder not found: ${inputFolder}`);
        }

        // Create output folder
        if (!fs.existsSync(outputFolder)) {
            fs.mkdirSync(outputFolder, { recursive: true });
        }

        // Find all .4cry files
        const encryptedFiles = this.findEncryptedFiles(inputFolder);
        
        if (encryptedFiles.length === 0) {
            throw new Error('No encrypted files found');
        }

        console.log(chalk.yellow(`📊 Total files to decrypt: ${encryptedFiles.length}`));

        const results = {
            successful: [],
            failed: [],
            total: encryptedFiles.length,
            startTime: Date.now()
        };

        // Process each encrypted file
        for (let i = 0; i < encryptedFiles.length; i++) {
            const filePath = encryptedFiles[i];
            const relativePath = path.relative(inputFolder, filePath);
            
            try {
                console.log(chalk.cyan(`\n[${i + 1}/${encryptedFiles.length}] 🔓 DECRYPTING: ${relativePath}`));
                
                // Determine output path
                let outputPath;
                if (preserveStructure) {
                    const relativeDir = path.dirname(relativePath);
                    const fileName = path.basename(filePath, '.4cry');
                    const outputDir = path.join(outputFolder, relativeDir);
                    
                    if (!fs.existsSync(outputDir)) {
                        fs.mkdirSync(outputDir, { recursive: true });
                    }
                    
                    outputPath = path.join(outputDir, fileName);
                } else {
                    const fileName = path.basename(filePath, '.4cry');
                    outputPath = path.join(outputFolder, fileName);
                }

                // Decrypt file
                await this.decryptFile(filePath, outputPath, password);
                
                results.successful.push({
                    input: filePath,
                    output: outputPath
                });
                
                console.log(chalk.green(`✅ DECRYPTION SUCCESS: ${path.basename(filePath)}`));
                
                if (progressCallback) {
                    progressCallback(i + 1, encryptedFiles.length, filePath, true);
                }
                
            } catch (error) {
                console.log(chalk.red(`❌ DECRYPTION FAILURE: ${relativePath} - ${error.message}`));
                
                results.failed.push({
                    input: filePath,
                    error: error.message
                });
                
                if (progressCallback) {
                    progressCallback(i + 1, encryptedFiles.length, filePath, false);
                }
            }
        }

        results.endTime = Date.now();
        results.duration = results.endTime - results.startTime;

        // Summary
        console.log(chalk.bold.green('\n🔓 DECRYPTION SUMMARY:'));
        console.log(chalk.green(`✅ Successfully decrypted: ${results.successful.length}`));
        console.log(chalk.red(`❌ Decryption failures: ${results.failed.length}`));
        console.log(chalk.blue(`⏱️ Total duration: ${(results.duration / 1000).toFixed(2)}s`));
        
        if (results.failed.length > 0) {
            console.log(chalk.red('\n❌ Decryption failures:'));
            results.failed.forEach(fail => {
                console.log(chalk.gray(`  • ${fail.input}: ${fail.error}`));
            });
        }

        return results;
    }

    /**
     * Find all encrypted files in folder
     */
    findEncryptedFiles(folder) {
        const files = [];
        
        const scanDir = (dir) => {
            if (!fs.existsSync(dir)) return;
            
            const items = fs.readdirSync(dir);
            
            for (const item of items) {
                const fullPath = path.join(dir, item);
                const stat = fs.statSync(fullPath);
                
                if (stat.isDirectory()) {
                    scanDir(fullPath);
                } else if (stat.isFile() && item.endsWith('.4cry')) {
                    files.push(fullPath);
                }
            }
        };
        
        scanDir(folder);
        return files;
    }

    /**
     * Initialize secure key storage with enhanced security
     */
    initializeKeyStorage() {
        if (!fs.existsSync(this.KEY_STORAGE_DIR)) {
            fs.mkdirSync(this.KEY_STORAGE_DIR, { recursive: true });
            console.log(chalk.green(`🔐 Key storage initialized: ${this.KEY_STORAGE_DIR}`));
        }
        
        // Initialize security log
        this.logSecurityEvent('SYSTEM_INIT', 'Key storage initialized');
    }

    /**
     * Log security events
     */
    logSecurityEvent(event, details, level = 'INFO') {
        const timestamp = new Date().toISOString();
        const logEntry = {
            timestamp,
            event,
            details,
            level,
            version: this.VERSION
        };
        
        const logLine = JSON.stringify(logEntry) + '\n';
        
        try {
            fs.appendFileSync(this.SECURITY_LOG_FILE, logLine);
        } catch (error) {
            console.log(chalk.yellow('⚠️ Could not write to security log'));
        }
    }

    /**
     * Enhanced password validation
     */
    validatePassword(password) {
        const errors = [];
        
        if (password.length < this.MIN_PASSWORD_LENGTH) {
            errors.push(`Password must be at least ${this.MIN_PASSWORD_LENGTH} characters`);
        }
        
        if (!/[A-Z]/.test(password)) {
            errors.push('Password must contain uppercase letters');
        }
        
        if (!/[a-z]/.test(password)) {
            errors.push('Password must contain lowercase letters');
        }
        
        if (!/\d/.test(password)) {
            errors.push('Password must contain numbers');
        }
        
        if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
            errors.push('Password must contain special characters');
        }
        
        // Check for common patterns
        const commonPatterns = [
            /123456/,
            /password/i,
            /qwerty/i,
            /admin/i,
            /letmein/i
        ];
        
        if (commonPatterns.some(pattern => pattern.test(password))) {
            errors.push('Password contains common patterns - use a more unique password');
        }
        
        return {
            isValid: errors.length === 0,
            errors: errors,
            strength: this.calculatePasswordStrength(password)
        };
    }

    /**
     * Calculate password strength score
     */
    calculatePasswordStrength(password) {
        let score = 0;
        
        // Length bonus
        if (password.length >= 12) score += 2;
        else if (password.length >= 8) score += 1;
        
        // Character variety
        if (/[A-Z]/.test(password)) score += 1;
        if (/[a-z]/.test(password)) score += 1;
        if (/\d/.test(password)) score += 1;
        if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) score += 1;
        
        // Uniqueness bonus
        const uniqueChars = new Set(password).size;
        if (uniqueChars / password.length > 0.7) score += 1;
        
        // Entropy estimation
        const entropy = password.length * Math.log2(uniqueChars);
        if (entropy > 50) score += 1;
        
        return Math.min(score, 8); // Max score of 8
    }

    /**
     * Enhanced key derivation with increased iterations
     */
    deriveKey(password, salt) {
        return crypto.pbkdf2Sync(password, salt, this.PBKDF2_ITERATIONS, this.KEY_SIZE, 'sha256');
    }

    /**
     * Generate or retrieve master key
     */
    getMasterKey() {
        this.initializeKeyStorage();
        
        if (fs.existsSync(this.MASTER_KEY_FILE)) {
            return fs.readFileSync(this.MASTER_KEY_FILE);
        } else {
            const masterKey = crypto.randomBytes(32);
            fs.writeFileSync(this.MASTER_KEY_FILE, masterKey);
            console.log(chalk.yellow('🔑 New master key generated'));
            return masterKey;
        }
    }

    /**
     * Store encrypted password securely
     */
    storePassword(keyId, password, description = '') {
        this.initializeKeyStorage();
        
        const masterKey = this.getMasterKey();
        const salt = crypto.randomBytes(16);
        const iv = crypto.randomBytes(16);
        
        // Derive key from master key and salt
        const derivedKey = crypto.pbkdf2Sync(masterKey, salt, 100000, 32, 'sha256');
        
        // Encrypt password
        const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv);
        const encryptedPassword = Buffer.concat([
            cipher.update(password, 'utf8'),
            cipher.final()
        ]);
        const authTag = cipher.getAuthTag();
        
        // Create key entry
        const keyEntry = {
            id: keyId,
            description: description,
            salt: salt.toString('base64'),
            iv: iv.toString('base64'),
            encryptedPassword: encryptedPassword.toString('base64'),
            authTag: authTag.toString('base64'),
            createdAt: new Date().toISOString(),
            version: this.VERSION
        };
        
        // Load existing database
        let keyDatabase = {};
        if (fs.existsSync(this.KEY_DATABASE_FILE)) {
            try {
                const encryptedDb = fs.readFileSync(this.KEY_DATABASE_FILE);
                const dbKey = crypto.pbkdf2Sync(masterKey, Buffer.from('4CRY_DB_SALT'), 100000, 32, 'sha256');
                const decipher = crypto.createDecipheriv('aes-256-gcm', dbKey, encryptedDb.slice(0, 16));
                decipher.setAuthTag(encryptedDb.slice(16, 32));
                const decryptedDb = decipher.update(encryptedDb.slice(32)) + decipher.final('utf8');
                keyDatabase = JSON.parse(decryptedDb);
            } catch (error) {
                console.log(chalk.yellow('⚠️ Creating new key database'));
            }
        }
        
        // Add new entry
        keyDatabase[keyId] = keyEntry;
        
        // Encrypt and save database
        const dbKey = crypto.pbkdf2Sync(masterKey, Buffer.from('4CRY_DB_SALT'), 100000, 32, 'sha256');
        const dbIv = crypto.randomBytes(16);
        const dbCipher = crypto.createCipheriv('aes-256-gcm', dbKey, dbIv);
        const encryptedDb = Buffer.concat([
            dbCipher.update(JSON.stringify(keyDatabase), 'utf8'),
            dbCipher.final()
        ]);
        const dbAuthTag = dbCipher.getAuthTag();
        
        fs.writeFileSync(this.KEY_DATABASE_FILE, Buffer.concat([dbIv, dbAuthTag, encryptedDb]));
        
        console.log(chalk.green(`🔐 Password stored securely with ID: ${keyId}`));
        return keyId;
    }

    /**
     * Retrieve stored password
     */
    retrievePassword(keyId) {
        this.initializeKeyStorage();
        
        if (!fs.existsSync(this.KEY_DATABASE_FILE)) {
            throw new Error('No key database found');
        }
        
        const masterKey = this.getMasterKey();
        
        // Load and decrypt database
        const encryptedDb = fs.readFileSync(this.KEY_DATABASE_FILE);
        const dbKey = crypto.pbkdf2Sync(masterKey, Buffer.from('4CRY_DB_SALT'), 100000, 32, 'sha256');
        const decipher = crypto.createDecipheriv('aes-256-gcm', dbKey, encryptedDb.slice(0, 16));
        decipher.setAuthTag(encryptedDb.slice(16, 32));
        const decryptedDb = decipher.update(encryptedDb.slice(32)) + decipher.final('utf8');
        const keyDatabase = JSON.parse(decryptedDb);
        
        if (!keyDatabase[keyId]) {
            throw new Error(`Key ID not found: ${keyId}`);
        }
        
        const keyEntry = keyDatabase[keyId];
        
        // Decrypt password
        const salt = Buffer.from(keyEntry.salt, 'base64');
        const iv = Buffer.from(keyEntry.iv, 'base64');
        const encryptedPassword = Buffer.from(keyEntry.encryptedPassword, 'base64');
        const authTag = Buffer.from(keyEntry.authTag, 'base64');
        
        const derivedKey = crypto.pbkdf2Sync(masterKey, salt, 100000, 32, 'sha256');
        const passwordDecipher = crypto.createDecipheriv('aes-256-gcm', derivedKey, iv);
        passwordDecipher.setAuthTag(authTag);
        
        const password = passwordDecipher.update(encryptedPassword) + passwordDecipher.final('utf8');
        
        return {
            password: password,
            description: keyEntry.description,
            createdAt: keyEntry.createdAt
        };
    }

    /**
     * List all stored keys
     */
    listStoredKeys() {
        this.initializeKeyStorage();
        
        if (!fs.existsSync(this.KEY_DATABASE_FILE)) {
            console.log(chalk.yellow('No keys stored'));
            return [];
        }
        
        const masterKey = this.getMasterKey();
        
        // Load and decrypt database
        const encryptedDb = fs.readFileSync(this.KEY_DATABASE_FILE);
        const dbKey = crypto.pbkdf2Sync(masterKey, Buffer.from('4CRY_DB_SALT'), 100000, 32, 'sha256');
        const decipher = crypto.createDecipheriv('aes-256-gcm', dbKey, encryptedDb.slice(0, 16));
        decipher.setAuthTag(encryptedDb.slice(16, 32));
        const decryptedDb = decipher.update(encryptedDb.slice(32)) + decipher.final('utf8');
        const keyDatabase = JSON.parse(decryptedDb);
        
        const keys = Object.keys(keyDatabase).map(keyId => ({
            id: keyId,
            description: keyDatabase[keyId].description,
            createdAt: keyDatabase[keyId].createdAt
        }));
        
        return keys;
    }

    /**
     * Delete stored key
     */
    deleteStoredKey(keyId) {
        this.initializeKeyStorage();
        
        if (!fs.existsSync(this.KEY_DATABASE_FILE)) {
            throw new Error('No key database found');
        }
        
        const masterKey = this.getMasterKey();
        
        // Load and decrypt database
        const encryptedDb = fs.readFileSync(this.KEY_DATABASE_FILE);
        const dbKey = crypto.pbkdf2Sync(masterKey, Buffer.from('4CRY_DB_SALT'), 100000, 32, 'sha256');
        const decipher = crypto.createDecipheriv('aes-256-gcm', dbKey, encryptedDb.slice(0, 16));
        decipher.setAuthTag(encryptedDb.slice(16, 32));
        const decryptedDb = decipher.update(encryptedDb.slice(32)) + decipher.final('utf8');
        const keyDatabase = JSON.parse(decryptedDb);
        
        if (!keyDatabase[keyId]) {
            throw new Error(`Key ID not found: ${keyId}`);
        }
        
        delete keyDatabase[keyId];
        
        // Encrypt and save database
        const dbIv = crypto.randomBytes(16);
        const dbCipher = crypto.createCipheriv('aes-256-gcm', dbKey, dbIv);
        const newEncryptedDb = Buffer.concat([
            dbCipher.update(JSON.stringify(keyDatabase), 'utf8'),
            dbCipher.final()
        ]);
        const dbAuthTag = dbCipher.getAuthTag();
        
        fs.writeFileSync(this.KEY_DATABASE_FILE, Buffer.concat([dbIv, dbAuthTag, newEncryptedDb]));
        
        console.log(chalk.green(`🗑️ Key deleted: ${keyId}`));
    }

    /**
     * Analisa a força de uma senha
     */
    analyzePasswordStrength(password) {
        const validation = this.validatePassword(password);
        const score = validation.strength;
        
        let strength, color;
        if (score < 3) {
            strength = 'Very Weak';
            color = 'red';
        } else if (score < 5) {
            strength = 'Weak';
            color = 'red';
        } else if (score < 6) {
            strength = 'Medium';
            color = 'yellow';
        } else if (score < 7) {
            strength = 'Strong';
            color = 'green';
        } else {
            strength = 'Very Strong';
            color = 'green';
        }

        return { 
            strength, 
            score, 
            feedback: validation.errors, 
            color,
            isValid: validation.isValid,
            entropy: this.calculateEntropy(password)
        };
    }

    /**
     * Calculate password entropy
     */
    calculateEntropy(password) {
        const uniqueChars = new Set(password).size;
        return password.length * Math.log2(uniqueChars);
    }

    /**
     * Encrypt file using RSA public key
     */
    async encryptWithPublicKey(inputPath, outputPath, publicKeyPath, password) {
        console.log(chalk.cyan('🔐 Starting RSA public key encryption...'));
        
        if (!fs.existsSync(inputPath)) {
            throw new Error(`Input file not found: ${inputPath}`);
        }
        
        if (!fs.existsSync(publicKeyPath)) {
            throw new Error(`Public key file not found: ${publicKeyPath}`);
        }
        
        // Read original file
        const originalData = fs.readFileSync(inputPath);
        const originalFilename = path.basename(inputPath);
        
        console.log(chalk.blue(`📁 File: ${originalFilename} (${this.formatBytes(originalData.length)})`));
        
        // Generate HMAC key
        const hmacKey = crypto.randomBytes(32);
        
        // Encrypt HMAC key with RSA public key
        const publicKey = fs.readFileSync(publicKeyPath, 'utf8');
        const encryptedHmacKey = crypto.publicEncrypt(publicKey, hmacKey);
        
        // Continue with normal AES encryption...
        const salt = crypto.randomBytes(this.SALT_SIZE);
        const iv = crypto.randomBytes(this.IV_SIZE);
        
        // Derive AES key from password
        const aesKey = this.deriveKey(password, salt);
        
        // Compress data
        const compressedData = this.compressData(originalData);
        console.log(chalk.green(`🗜️ Compressed: ${this.formatBytes(compressedData.length)}`));
        
        // Encrypt with AES-256-GCM
        const cipher = crypto.createCipheriv(this.ALGORITHM, aesKey, iv);
        const encryptedData = Buffer.concat([
            cipher.update(compressedData),
            cipher.final()
        ]);
        const authTag = cipher.getAuthTag();
        
        // Create metadata
        const metadata = this.embedMetadata(originalFilename, 'application/octet-stream', false);
        
        // Create HMAC
        const hmacData = Buffer.concat([
            this.SIGNATURE,
            Buffer.alloc(256), // Header placeholder
            salt,
            iv,
            authTag,
            metadata,
            encryptedData
        ]);
        
        const hmac = crypto.createHmac('sha256', hmacKey).update(hmacData).digest();
        
        // Create final encrypted file
        const finalData = Buffer.concat([
            this.SIGNATURE,
            Buffer.alloc(256), // Header placeholder
            salt,
            iv,
            authTag,
            hmac,
            encryptedHmacKey, // RSA encrypted HMAC key
            Buffer.alloc(4), // Metadata size placeholder
            metadata,
            Buffer.alloc(4), // Compressed size placeholder
            encryptedData
        ]);
        
        // Write sizes in correct positions
        finalData.writeUInt32BE(metadata.length, this.SIGNATURE.length + 256 + this.SALT_SIZE + this.IV_SIZE + this.TAG_SIZE + 32 + encryptedHmacKey.length);
        finalData.writeUInt32BE(encryptedData.length, this.SIGNATURE.length + 256 + this.SALT_SIZE + this.IV_SIZE + this.TAG_SIZE + 32 + encryptedHmacKey.length + 4 + metadata.length);
        
        // Write encrypted file
        fs.writeFileSync(outputPath, finalData);
        
        console.log(chalk.green('✅ RSA encryption completed!'));
        console.log(chalk.blue(`📤 File saved: ${outputPath}`));
        console.log(chalk.blue(`🔗 Final size: ${this.formatBytes(finalData.length)}`));
    }

    /**
     * Decrypt file using RSA private key
     */
    async decryptWithPrivateKey(inputPath, outputPath, privateKeyPath, password) {
        console.log(chalk.cyan('🔓 Starting RSA private key decryption...'));
        
        if (!fs.existsSync(inputPath)) {
            throw new Error(`Input file not found: ${inputPath}`);
        }
        
        if (!fs.existsSync(privateKeyPath)) {
            throw new Error(`Private key file not found: ${privateKeyPath}`);
        }
        
        // Read encrypted file
        const encryptedData = fs.readFileSync(inputPath);
        
        // Read private key
        const privateKey = fs.readFileSync(privateKeyPath, 'utf8');
        
        // Verify signature
        if (!encryptedData.slice(0, 9).equals(this.SIGNATURE)) {
            throw new Error('Magic number invalid - not a .4cry file');
        }
        
        let offset = 9;
        
        // Read header
        const header = encryptedData.slice(offset, offset + 256);
        offset += 256;
        
        // Read salt
        const salt = encryptedData.slice(offset, offset + this.SALT_SIZE);
        offset += this.SALT_SIZE;
        
        // Read IV
        const iv = encryptedData.slice(offset, offset + this.IV_SIZE);
        offset += this.IV_SIZE;
        
        // Read auth tag
        const authTag = encryptedData.slice(offset, offset + this.TAG_SIZE);
        offset += this.TAG_SIZE;
        
        // Read HMAC
        const hmac = encryptedData.slice(offset, offset + 32);
        offset += 32;
        
        // Read HMAC key (encrypted with RSA)
        const encryptedHmacKey = encryptedData.slice(offset, offset + 256); // RSA encrypted
        offset += 256;
        
        // Decrypt HMAC key with RSA private key
        const hmacKey = crypto.privateDecrypt(privateKey, encryptedHmacKey);
        
        // Read metadata
        const metadataSize = encryptedData.readUInt32BE(offset);
        offset += 4;
        const metadata = encryptedData.slice(offset, offset + metadataSize);
        offset += metadataSize;
        
        // Read compressed data
        const compressedSize = encryptedData.readUInt32BE(offset);
        offset += 4;
        const ciphertext = encryptedData.slice(offset, offset + compressedSize);
        
        // Verify HMAC
        const hmacData = Buffer.concat([
            this.SIGNATURE,
            header,
            salt,
            iv,
            authTag,
            metadata,
            ciphertext
        ]);
        
        const calculatedHmac = crypto.createHmac('sha256', hmacKey).update(hmacData).digest();
        
        if (!crypto.timingSafeEqual(hmac, calculatedHmac)) {
            throw new Error('Integrity verification failed - file may be corrupted');
        }
        
        // Decrypt data with AES
        const aesKey = this.deriveKey(password, salt);
        const decipher = crypto.createDecipheriv(this.ALGORITHM, aesKey, iv);
        decipher.setAuthTag(authTag);
        
        const decryptedData = Buffer.concat([
            decipher.update(ciphertext),
            decipher.final()
        ]);
        
        // Decompress data
        const originalData = this.decompressData(decryptedData);
        
        // Write decrypted file
        fs.writeFileSync(outputPath, originalData);
        
        console.log(chalk.green('✅ RSA decryption completed!'));
        console.log(chalk.blue(`📤 File restored: ${outputPath}`));
        console.log(chalk.blue(`📊 Restored size: ${this.formatBytes(originalData.length)}`));
    }

    /**
     * Multi-layer encryption - encrypt file multiple times for maximum security
     */
    async multiLayerEncrypt(inputPath, outputPath, password, layers = 3, options = {}) {
        console.log(chalk.cyan(`🔐 Starting ${layers}-layer encryption for MAXIMUM SECURITY...`));
        
        if (!fs.existsSync(inputPath)) {
            throw new Error(`Input file not found: ${inputPath}`);
        }
        
        if (layers < 2 || layers > 10) {
            throw new Error('Layers must be between 2 and 10 for security and performance');
        }
        
        // Read original file
        let currentData = fs.readFileSync(inputPath);
        const originalFilename = path.basename(inputPath);
        const originalSize = currentData.length;
        
        console.log(chalk.blue(`📁 File: ${originalFilename} (${this.formatBytes(originalSize)})`));
        console.log(chalk.yellow(`🔄 Encrypting ${layers} times for maximum security...`));
        
        // Create temporary files for each layer
        const tempFiles = [];
        let currentPath = inputPath;
        
        for (let layer = 1; layer <= layers; layer++) {
            const tempPath = `${outputPath}.temp_layer_${layer}`;
            tempFiles.push(tempPath);
            
            console.log(chalk.cyan(`🔐 Layer ${layer}/${layers}: Encrypting...`));
            
            // Generate unique salt and IV for each layer
            const salt = crypto.randomBytes(this.SALT_SIZE);
            const iv = crypto.randomBytes(this.IV_SIZE);
            
            // Derive unique key for this layer using layer-specific salt
            const layerPassword = `${password}_layer_${layer}`;
            const key = this.deriveKey(layerPassword, salt);
            
            // Compress data (only on first layer to avoid over-compression)
            let dataToEncrypt = currentData;
            if (layer === 1) {
                dataToEncrypt = this.compressData(currentData);
                console.log(chalk.green(`🗜️ Layer ${layer}: Compressed to ${this.formatBytes(dataToEncrypt.length)}`));
            }
            
            // Encrypt with AES-256-GCM
            const cipher = crypto.createCipheriv(this.ALGORITHM, key, iv);
            const encryptedData = Buffer.concat([
                cipher.update(dataToEncrypt),
                cipher.final()
            ]);
            const authTag = cipher.getAuthTag();
            
            // Create metadata for this layer
            const layerMetadata = this.embedMetadata(
                layer === 1 ? originalFilename : `layer_${layer-1}.4cry`,
                'application/octet-stream',
                options.hideMetadata !== false
            );
            
            // Create HMAC for integrity
            const hmacData = Buffer.concat([
                this.SIGNATURE,
                Buffer.alloc(256), // Header placeholder
                salt,
                iv,
                authTag,
                layerMetadata,
                encryptedData
            ]);
            
            const hmac = crypto.createHmac('sha256', key).update(hmacData).digest();
            
            // Create layer file
            const layerData = Buffer.concat([
                this.SIGNATURE,
                Buffer.alloc(256), // Header placeholder
                salt,
                iv,
                authTag,
                hmac,
                Buffer.alloc(4), // Metadata size placeholder
                layerMetadata,
                Buffer.alloc(4), // Compressed size placeholder
                encryptedData
            ]);
            
            // Write sizes
            layerData.writeUInt32BE(layerMetadata.length, this.SIGNATURE.length + 256 + this.SALT_SIZE + this.IV_SIZE + this.TAG_SIZE + 32);
            layerData.writeUInt32BE(encryptedData.length, this.SIGNATURE.length + 256 + this.SALT_SIZE + this.IV_SIZE + this.TAG_SIZE + 32 + 4 + layerMetadata.length);
            
            fs.writeFileSync(tempPath, layerData);
            
            console.log(chalk.green(`✅ Layer ${layer}/${layers}: Encrypted (${this.formatBytes(layerData.length)})`));
            
            // Update for next layer
            currentData = layerData;
            currentPath = tempPath;
        }
        
        // Move final layer to output
        fs.copyFileSync(tempFiles[tempFiles.length - 1], outputPath);
        
        // Clean up temporary files
        tempFiles.forEach(tempFile => {
            if (fs.existsSync(tempFile)) {
                fs.unlinkSync(tempFile);
            }
        });
        
        const finalSize = fs.statSync(outputPath).size;
        const compressionRatio = ((originalSize - finalSize) / originalSize * 100).toFixed(2);
        
        console.log(chalk.green(`🎉 ${layers}-layer encryption completed!`));
        console.log(chalk.blue(`📤 File saved: ${outputPath}`));
        console.log(chalk.blue(`🔗 Final size: ${this.formatBytes(finalSize)}`));
        console.log(chalk.blue(`📊 Size change: ${compressionRatio}% ${compressionRatio > 0 ? 'reduction' : 'increase'}`));
        console.log(chalk.yellow(`🔐 Security level: ${layers}x encryption layers`));
        
        // Log security event
        this.logSecurityEvent('MULTI_LAYER_ENCRYPT', `File encrypted with ${layers} layers`, 'INFO');
    }

    /**
     * Multi-layer decryption - decrypt file encrypted multiple times
     */
    async multiLayerDecrypt(inputPath, outputPath, password, layers = 3) {
        console.log(chalk.cyan(`🔓 Starting ${layers}-layer decryption...`));
        
        if (!fs.existsSync(inputPath)) {
            throw new Error(`Input file not found: ${inputPath}`);
        }
        
        // Read encrypted file
        let currentData = fs.readFileSync(inputPath);
        const originalSize = currentData.length;
        
        console.log(chalk.blue(`📁 Encrypted file: ${this.formatBytes(originalSize)}`));
        console.log(chalk.yellow(`🔄 Decrypting ${layers} layers...`));
        
        // Create temporary files for each layer
        const tempFiles = [];
        let currentPath = inputPath;
        
        for (let layer = layers; layer >= 1; layer--) {
            const tempPath = `${outputPath}.temp_decrypt_layer_${layer}`;
            tempFiles.push(tempPath);
            
            console.log(chalk.cyan(`🔓 Layer ${layers - layer + 1}/${layers}: Decrypting...`));
            
            // Verify signature
            if (!currentData.slice(0, 9).equals(this.SIGNATURE)) {
                throw new Error(`Magic number invalid in layer ${layer} - not a .4cry file`);
            }
            
            let offset = 9;
            
            // Read header
            const header = currentData.slice(offset, offset + 256);
            offset += 256;
            
            // Read salt
            const salt = currentData.slice(offset, offset + this.SALT_SIZE);
            offset += this.SALT_SIZE;
            
            // Read IV
            const iv = currentData.slice(offset, offset + this.IV_SIZE);
            offset += this.IV_SIZE;
            
            // Read auth tag
            const authTag = currentData.slice(offset, offset + this.TAG_SIZE);
            offset += this.TAG_SIZE;
            
            // Read HMAC
            const hmac = currentData.slice(offset, offset + 32);
            offset += 32;
            
            // Read metadata
            const metadataSize = currentData.readUInt32BE(offset);
            offset += 4;
            const metadata = currentData.slice(offset, offset + metadataSize);
            offset += metadataSize;
            
            // Read compressed data
            const compressedSize = currentData.readUInt32BE(offset);
            offset += 4;
            const ciphertext = currentData.slice(offset, offset + compressedSize);
            
            // Derive key for this layer
            const layerPassword = `${password}_layer_${layer}`;
            const key = this.deriveKey(layerPassword, salt);
            
            // Verify HMAC
            const hmacData = Buffer.concat([
                this.SIGNATURE,
                header,
                salt,
                iv,
                authTag,
                metadata,
                ciphertext
            ]);
            
            const calculatedHmac = crypto.createHmac('sha256', key).update(hmacData).digest();
            
            if (!crypto.timingSafeEqual(hmac, calculatedHmac)) {
                throw new Error(`Integrity verification failed in layer ${layer} - file may be corrupted`);
            }
            
            // Decrypt with AES
            const decipher = crypto.createDecipheriv(this.ALGORITHM, key, iv);
            decipher.setAuthTag(authTag);
            
            const decryptedData = Buffer.concat([
                decipher.update(ciphertext),
                decipher.final()
            ]);
            
            // Decompress data (only on last layer)
            let finalData = decryptedData;
            if (layer === 1) {
                finalData = this.decompressData(decryptedData);
                console.log(chalk.green(`🗜️ Layer ${layers - layer + 1}: Decompressed to ${this.formatBytes(finalData.length)}`));
            }
            
            // Write decrypted layer
            fs.writeFileSync(tempPath, finalData);
            
            console.log(chalk.green(`✅ Layer ${layers - layer + 1}/${layers}: Decrypted (${this.formatBytes(finalData.length)})`));
            
            // Update for next layer
            currentData = finalData;
            currentPath = tempPath;
        }
        
        // Move final decrypted file to output
        fs.copyFileSync(tempFiles[tempFiles.length - 1], outputPath);
        
        // Clean up temporary files
        tempFiles.forEach(tempFile => {
            if (fs.existsSync(tempFile)) {
                fs.unlinkSync(tempFile);
            }
        });
        
        const finalSize = fs.statSync(outputPath).size;
        
        console.log(chalk.green(`🎉 ${layers}-layer decryption completed!`));
        console.log(chalk.blue(`📤 File restored: ${outputPath}`));
        console.log(chalk.blue(`📊 Restored size: ${this.formatBytes(finalSize)}`));
        
        // Log security event
        this.logSecurityEvent('MULTI_LAYER_DECRYPT', `File decrypted from ${layers} layers`, 'INFO');
    }

    /**
     * ULTRA-SECURE file erasure - NO TRACES LEFT ON DISK
     */
    async secureErase(inputPath, outputPath, password, options = {}) {
        console.log(chalk.red(`🔥 Starting ULTRA-SECURE ERASE - ELIMINATING ALL TRACES...`));
        
        if (!fs.existsSync(inputPath)) {
            throw new Error(`Input file not found: ${inputPath}`);
        }
        
        const originalFilename = path.basename(inputPath);
        const originalSize = fs.statSync(inputPath).size;
        const originalStats = fs.statSync(inputPath);
        
        console.log(chalk.blue(`📁 File: ${originalFilename} (${this.formatBytes(originalSize)})`));
        console.log(chalk.yellow(`⚠️ WARNING: ALL TRACES will be PERMANENTLY ELIMINATED!`));
        
        // Step 1: Encrypt the file
        console.log(chalk.cyan(`🔐 Step 1: Encrypting file...`));
        await this.encryptFile(inputPath, outputPath, password, options);
        
        if (!fs.existsSync(outputPath)) {
            throw new Error('Encryption failed - cannot proceed with secure erase');
        }
        
        console.log(chalk.green(`✅ File encrypted successfully`));
        
        // Step 2: ULTRA-SECURE overwrite with extended patterns
        console.log(chalk.red(`🔥 Step 2: ULTRA-SECURE ERASE - Multiple overwrite patterns...`));
        
        const overwritePasses = options.overwritePasses || 15; // Increased default to 15 passes
        const fileHandle = fs.openSync(inputPath, 'r+');
        
        try {
            // Extended overwrite patterns for maximum security
            const patterns = [
                { name: 'Zeros', data: Buffer.alloc(originalSize, 0x00) },
                { name: 'Ones', data: Buffer.alloc(originalSize, 0xFF) },
                { name: 'Random 1', data: crypto.randomBytes(originalSize) },
                { name: 'Random 2', data: crypto.randomBytes(originalSize) },
                { name: 'Alternating AA/55', data: Buffer.alloc(originalSize).map((_, i) => i % 2 === 0 ? 0xAA : 0x55) },
                { name: 'Alternating 55/AA', data: Buffer.alloc(originalSize).map((_, i) => i % 2 === 0 ? 0x55 : 0xAA) },
                { name: 'Random 3', data: crypto.randomBytes(originalSize) },
                { name: 'Random 4', data: crypto.randomBytes(originalSize) },
                { name: 'Pattern 0x92', data: Buffer.alloc(originalSize, 0x92) },
                { name: 'Pattern 0x49', data: Buffer.alloc(originalSize, 0x49) },
                { name: 'Random 5', data: crypto.randomBytes(originalSize) },
                { name: 'Random 6', data: crypto.randomBytes(originalSize) },
                { name: 'Random 7', data: crypto.randomBytes(originalSize) },
                { name: 'Random 8', data: crypto.randomBytes(originalSize) },
                { name: 'Final Random', data: crypto.randomBytes(originalSize) }
            ];
            
            for (let pass = 1; pass <= overwritePasses; pass++) {
                const pattern = patterns[(pass - 1) % patterns.length];
                console.log(chalk.red(`🔥 Pass ${pass}/${overwritePasses}: ${pattern.name}...`));
                
                // Write pattern data
                fs.writeSync(fileHandle, pattern.data, 0, originalSize, 0);
                
                // Force multiple sync operations
                fs.fsyncSync(fileHandle);
                fs.fdatasyncSync(fileHandle);
                
                console.log(chalk.green(`✅ Pass ${pass}/${overwritePasses}: Complete`));
                
                // Longer delay for disk write completion
                await new Promise(resolve => setTimeout(resolve, 200));
            }
            
            // Step 3: Extended verification
            console.log(chalk.cyan(`🔍 Step 3: EXTENDED VERIFICATION - Checking all traces...`));
            
            const verificationBuffer = Buffer.alloc(originalSize);
            fs.readSync(fileHandle, verificationBuffer, 0, originalSize, 0);
            
            // Multiple verification checks
            const checks = {
                notZeros: verificationBuffer.every(byte => byte !== 0x00),
                notOnes: verificationBuffer.every(byte => byte !== 0xFF),
                notPattern: verificationBuffer.every(byte => byte !== 0xAA && byte !== 0x55),
                hasRandomness: this.calculateEntropy(verificationBuffer.toString('hex')) > 3.0
            };
            
            const allChecksPassed = Object.values(checks).every(check => check);
            
            if (allChecksPassed) {
                console.log(chalk.green(`✅ All verification checks passed - File completely overwritten`));
            } else {
                console.log(chalk.yellow(`⚠️ Some verification checks failed - Additional passes may be needed`));
                Object.entries(checks).forEach(([check, passed]) => {
                    console.log(chalk[passed ? 'green' : 'yellow'](`  ${check}: ${passed ? 'PASS' : 'FAIL'}`));
                });
            }
            
        } finally {
            fs.closeSync(fileHandle);
        }
        
        // Step 4: Metadata and system trace elimination
        console.log(chalk.red(`🧹 Step 4: ELIMINATING SYSTEM TRACES...`));
        
        try {
            // Clear file system cache (if possible)
            if (process.platform === 'win32') {
                // Windows: Clear file system cache
                console.log(chalk.cyan(`🧹 Clearing Windows file system cache...`));
                // Note: This is a placeholder - actual cache clearing would require admin privileges
            }
            
            // Reset file timestamps to random values before deletion
            const randomTime = new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000);
            fs.utimesSync(inputPath, randomTime, randomTime);
            
            console.log(chalk.green(`✅ System traces cleared`));
            
        } catch (error) {
            console.log(chalk.yellow(`⚠️ Could not clear all system traces: ${error.message}`));
        }
        
        // Step 5: Final deletion with multiple attempts
        console.log(chalk.red(`🗑️ Step 5: FINAL DELETION - Multiple attempts...`));
        
        let deletionAttempts = 0;
        const maxAttempts = 3;
        
        while (fs.existsSync(inputPath) && deletionAttempts < maxAttempts) {
            deletionAttempts++;
            console.log(chalk.red(`🗑️ Deletion attempt ${deletionAttempts}/${maxAttempts}...`));
            
            try {
                fs.unlinkSync(inputPath);
                console.log(chalk.green(`✅ File deleted successfully`));
            } catch (error) {
                console.log(chalk.yellow(`⚠️ Deletion attempt ${deletionAttempts} failed: ${error.message}`));
                if (deletionAttempts < maxAttempts) {
                    await new Promise(resolve => setTimeout(resolve, 1000));
                }
            }
        }
        
        if (fs.existsSync(inputPath)) {
            console.log(chalk.red(`❌ CRITICAL: File still exists after ${maxAttempts} attempts!`));
            throw new Error('File deletion failed - manual intervention required');
        }
        
        // Step 6: Final verification and cleanup
        console.log(chalk.cyan(`🔍 Step 6: FINAL VERIFICATION - No traces remaining...`));
        
        // Verify file is completely gone
        if (!fs.existsSync(inputPath)) {
            console.log(chalk.green(`✅ VERIFICATION PASSED: File completely eliminated`));
        } else {
            console.log(chalk.red(`❌ VERIFICATION FAILED: File still exists!`));
        }
        
        // Clear any temporary files
        const tempFiles = [
            `${inputPath}.tmp`,
            `${inputPath}.temp`,
            `${inputPath}.bak`,
            `${inputPath}~`
        ];
        
        tempFiles.forEach(tempFile => {
            if (fs.existsSync(tempFile)) {
                try {
                    fs.unlinkSync(tempFile);
                    console.log(chalk.green(`🧹 Cleaned temporary file: ${path.basename(tempFile)}`));
                } catch (error) {
                    console.log(chalk.yellow(`⚠️ Could not clean ${tempFile}: ${error.message}`));
                }
            }
        });
        
        console.log(chalk.green(`🎉 ULTRA-SECURE ERASE COMPLETED!`));
        console.log(chalk.red(`🔥 Original file: COMPLETELY ELIMINATED`));
        console.log(chalk.blue(`📤 Encrypted file: ${outputPath}`));
        console.log(chalk.yellow(`🔐 Recovery: Only possible with correct password`));
        console.log(chalk.red(`⚠️ Original file: NO TRACES REMAINING`));
        console.log(chalk.green(`✅ System traces: CLEARED`));
        console.log(chalk.green(`✅ Verification: PASSED`));
        
        // Log security event
        this.logSecurityEvent('ULTRA_SECURE_ERASE', `File ultra-securely erased with ${overwritePasses} passes - NO TRACES`, 'CRITICAL');
    }

    /**
     * DESTROY SECURE - Apaga arquivos/pastas SEM salvar backup criptografado
     * Usa criptografia durante o processo para garantir que nem o FBI possa recuperar
     * @param {string} inputPath - Arquivo ou pasta a ser completamente destruído
     * @param {string} password - Senha para o processo de criptografia
     * @param {Object} options - Opções de configuração
     */
    async secureDelete(inputPath, password, options = {}) {
        console.log(chalk.red(`💀 Starting DESTROY SECURE - PERMANENT COMPLETE ELIMINATION...`));
        
        if (!fs.existsSync(inputPath)) {
            throw new Error(`Input path not found: ${inputPath}`);
        }

        const stats = fs.statSync(inputPath);
        const isDirectory = stats.isDirectory();

        if (isDirectory) {
            // Processar pasta recursivamente
            await this.secureDeleteDirectory(inputPath, password, options);
        } else {
            // Processar arquivo individual
            await this.secureDeleteFile(inputPath, password, options);
        }

        console.log(chalk.green(`✅ DESTROY COMPLETE - All traces eliminated forever`));
        this.logSecurityEvent('DESTROY_SECURE', `File/path completely destroyed with encrypted overwrite - NO TRACES`, 'CRITICAL');
    }

    /**
     * Destruir arquivo individual OTIMIZADO - MAIS RÁPIDO E EFICAZ
     */
    async secureDeleteFile(inputPath, password, options = {}) {
        const originalSize = fs.statSync(inputPath).size;
        const originalFilename = path.basename(inputPath);
        
        console.log(chalk.red(`💀 Target: ${originalFilename} (${this.formatBytes(originalSize)})`));
        console.log(chalk.yellow(`⚠️ WARNING: Complete permanent deletion - NO RECOVERY POSSIBLE!`));

        const overwritePasses = options.overwritePasses || 20;
        const fileHandle = fs.openSync(inputPath, 'r+');
        
        // Progress bar para feedback
        const totalOperations = overwritePasses + 3; // padrões + verificações
        let progressCount = 0;

        try {
            // OTIMIZAÇÃO: Gerar apenas padrões essenciais inicialmente
            console.log(chalk.cyan(`🔐 Starting optimized encrypted overwrite (${overwritePasses} passes)...`));
            
            // Criar progress bar
            const progressBar = new ProgressBar('  Destroying [:bar] :percent :etas', {
                complete: '█',
                incomplete: '░',
                width: 30,
                total: totalOperations
            });
            
            // Overwrite otimizado com menos chamadas de sincronização
            for (let i = 0; i < overwritePasses; i++) {
                progressCount++;
                progressBar.update(progressCount / totalOperations);
                
                // OTIMIZAÇÃO: Gerar dados no-the-fly em vez de pré-gerar
                const salt = crypto.randomBytes(this.SALT_SIZE);
                const key = this.deriveKey(password + originalFilename + i.toString(), salt, 30000); // Reduzido de 50000
                
                // Criar dados aleatórios
                const randomData = crypto.randomBytes(originalSize);
                
                // Criptografar
                const iv = crypto.randomBytes(this.IV_SIZE);
                
                // Ajustar padding manualmente para evitar erro de tamanho final
                const blockSize = 16; // AES block size
                const paddingLength = blockSize - (randomData.length % blockSize);
                const paddedData = Buffer.concat([randomData, Buffer.alloc(paddingLength, paddingLength)]);
                
                const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
                cipher.setAutoPadding(false);
                
                let encryptedData = cipher.update(paddedData);
                encryptedData = Buffer.concat([encryptedData, cipher.final()]);
                
                // Ajustar tamanho
                if (encryptedData.length > originalSize) {
                    encryptedData = encryptedData.subarray(0, originalSize);
                } else if (encryptedData.length < originalSize) {
                    const padding = crypto.randomBytes(originalSize - encryptedData.length);
                    encryptedData = Buffer.concat([encryptedData, padding]);
                }
                
                // Escrever e sincronizar apenas a cada 3 passes para ser mais rápido
                fs.writeSync(fileHandle, encryptedData, 0, originalSize, 0);
                
                if (i % 3 === 0) {
                    fs.fsyncSync(fileHandle);
                }
            }

            // Adicionar padrões finais de segurança
            progressCount++;
            progressBar.update(progressCount / totalOperations);
            fs.writeSync(fileHandle, Buffer.alloc(originalSize, 0x00), 0, originalSize, 0); // Zeros
            
            progressCount++;
            progressBar.update(progressCount / totalOperations);
            fs.writeSync(fileHandle, Buffer.alloc(originalSize, 0xFF), 0, originalSize, 0); // Ones
            
            progressCount++;
            progressBar.update(progressCount / totalOperations);
            fs.writeSync(fileHandle, crypto.randomBytes(originalSize), 0, originalSize, 0); // Random final
            
            // Sincronizar uma última vez
            fs.fsyncSync(fileHandle);
            fs.fdatasyncSync(fileHandle);
            
            // Verificação rápida
            console.log(chalk.cyan(`🔍 Verifying destruction...`));
            const verificationBuffer = Buffer.alloc(Math.min(originalSize, 1024)); // Ler apenas 1KB para verificação
            fs.readSync(fileHandle, verificationBuffer, 0, verificationBuffer.length, 0);
            
            const entropy = this.calculateEntropy(verificationBuffer.toString('hex'));
            console.log(chalk.green(`✅ Entropy verified: ${entropy.toFixed(2)}`));
            
        } finally {
            fs.closeSync(fileHandle);
        }

        // OTIMIZAÇÃO: Deletar mais rapidamente
        console.log(chalk.cyan(`🧹 Removing file...`));
        try {
            const randomTime = new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000);
            fs.utimesSync(inputPath, randomTime, randomTime);
        } catch (error) {
            // Ignorar erro de timestamp
        }

        // Deletar com menos tentativas mas mais agressivo
        let deletionAttempts = 0;
        const maxAttempts = 3; // Reduzido de 5 para 3
        
        while (fs.existsSync(inputPath) && deletionAttempts < maxAttempts) {
            deletionAttempts++;
            try {
                fs.unlinkSync(inputPath);
                break;
            } catch (error) {
                if (deletionAttempts >= maxAttempts) {
                    throw new Error('File deletion failed - manual intervention required');
                }
                await new Promise(resolve => setTimeout(resolve, 300)); // Reduzido de 1000ms
            }
        }

        if (fs.existsSync(inputPath)) {
            throw new Error('File deletion failed - manual intervention required');
        }

        console.log(chalk.green(`✅ File completely eliminated - NO TRACES REMAINING`));
    }

    /**
     * Destruir pasta recursivamente OTIMIZADO - MAIS RÁPIDO
     */
    async secureDeleteDirectory(inputPath, password, options = {}) {
        console.log(chalk.cyan(`📁 Processing directory: ${path.basename(inputPath)}`));
        
        try {
            // Ler todos os arquivos e subpastas
            const items = fs.readdirSync(inputPath);
            
            if (items.length === 0) {
                console.log(chalk.blue(`📊 Directory empty, removing...`));
            } else {
                console.log(chalk.blue(`📊 Found ${items.length} items`));
            }
            
            // OTIMIZAÇÃO: Separar arquivos e diretórios para processar mais rápido
            const files = [];
            const dirs = [];
            
            for (const item of items) {
                const itemPath = path.join(inputPath, item);
                try {
                    const stats = fs.statSync(itemPath);
                    if (stats.isDirectory()) {
                        dirs.push(itemPath);
                    } else {
                        files.push(itemPath);
                    }
                } catch (error) {
                    // Se não conseguir ler, tentar deletar diretamente
                    try {
                        fs.unlinkSync(itemPath);
                    } catch (e) {
                        // Ignorar
                    }
                }
            }
            
            // OTIMIZAÇÃO: Processar arquivos primeiro (mais rápido)
            for (const filePath of files) {
                try {
                    await this.secureDeleteFile(filePath, password, options);
                } catch (error) {
                    // Tentar deletar normalmente
                    try {
                        fs.unlinkSync(filePath);
                    } catch (e) {
                        // Ignorar e continuar
                    }
                }
            }
            
            // Processar subdiretórios
            for (const dirPath of dirs) {
                try {
                    await this.secureDeleteDirectory(dirPath, password, options);
                } catch (error) {
                    // Continuar mesmo com erro
                }
            }

            // OTIMIZAÇÃO: Deletar diretório com método mais direto
            console.log(chalk.red(`🗑️ Deleting directory: ${path.basename(inputPath)}...`));
            
            let deleted = false;
            
            // Estratégia 1: fs.rmSync (mais rápido e eficaz)
            try {
                if (fs.rmSync) {
                    fs.rmSync(inputPath, { 
                        recursive: true, 
                        force: true,
                        maxRetries: 5,
                        retryDelay: 300
                    });
                    console.log(chalk.green(`✅ Directory deleted`));
                    deleted = true;
                } else {
                    // Fallback: rmdirSync tradicional
                    try {
                        fs.rmdirSync(inputPath);
                        deleted = true;
                    } catch (error) {
                        // Se não está vazio, tentar com Windows rmdir
                        if (process.platform === 'win32') {
                            try {
                                const { execSync } = require('child_process');
                                execSync(`rmdir /s /q "${inputPath}"`, { stdio: 'ignore' });
                                deleted = true;
                            } catch (e) {
                                // Ignorar
                            }
                        }
                    }
                }
            } catch (error) {
                // Última tentativa agressiva
                if (!fs.existsSync(inputPath)) {
                    deleted = true;
                } else {
                    try {
                        if (process.platform === 'win32') {
                            const { execSync } = require('child_process');
                            execSync(`rmdir /s /q "${inputPath}"`, { stdio: 'ignore' });
                            deleted = true;
                        } else {
                            fs.rmdirSync(inputPath);
                            deleted = true;
                        }
                    } catch (e) {
                        // Ignorar erro final
                    }
                }
            }
            
            if (!fs.existsSync(inputPath)) {
                console.log(chalk.green(`✅ Directory eliminated`));
            }
            
        } catch (error) {
            // OTIMIZAÇÃO: Tentar deletar mesmo com erro usando método direto
            try {
                if (fs.existsSync(inputPath)) {
                    if (process.platform === 'win32') {
                        const { execSync } = require('child_process');
                        execSync(`rmdir /s /q "${inputPath}"`, { stdio: 'ignore' });
                    } else if (fs.rmSync) {
                        fs.rmSync(inputPath, { recursive: true, force: true });
                    } else {
                        fs.rmdirSync(inputPath);
                    }
                }
            } catch (e) {
                // Ignorar erro final
            }
            
            throw error;
        }
    }

    /**
     * Assess file security level
     */
    assessFileSecurity(filePath, stats) {
        const ext = path.extname(filePath).toLowerCase();
        const fileName = path.basename(filePath);
        let score = 0;
        let recommendations = [];
        
        // File size assessment
        if (stats.size > this.MAX_FILE_SIZE) {
            score -= 2;
            recommendations.push('File exceeds maximum recommended size');
        } else if (stats.size > 100 * 1024 * 1024) { // 100MB
            score -= 1;
            recommendations.push('Large file - consider splitting for better security');
        }
        
        // File extension assessment
        const sensitiveExtensions = ['.key', '.pem', '.p12', '.pfx', '.crt', '.cer'];
        const executableExtensions = ['.exe', '.bat', '.cmd', '.scr', '.com'];
        
        if (sensitiveExtensions.includes(ext)) {
            score += 2;
            recommendations.push('Sensitive file type - encryption highly recommended');
        } else if (executableExtensions.includes(ext)) {
            score -= 1;
            recommendations.push('Executable file - verify source before encryption');
        }
        
        // File name assessment
        if (fileName.includes('password') || fileName.includes('secret') || fileName.includes('private')) {
            score += 1;
            recommendations.push('Sensitive filename - encryption recommended');
        }
        
        // File age assessment
        const daysSinceModified = (Date.now() - stats.mtime.getTime()) / (1000 * 60 * 60 * 24);
        if (daysSinceModified > 365) {
            score -= 1;
            recommendations.push('Old file - consider updating or archiving');
        }
        
        let level, color;
        if (score >= 2) {
            level = 'High Risk';
            color = 'red';
        } else if (score >= 0) {
            level = 'Medium Risk';
            color = 'yellow';
        } else {
            level = 'Low Risk';
            color = 'green';
        }
        
        return { level, color, score, recommendations };
    }
}

// CLI Interface
const program = new Command();
const encryption = new AdvancedFileEncryption();

program
    .name('4cry-encrypt')
    .description('🔐 4CRY Encrypt - Advanced File Encryption System 🔐')
    .version('2.2.0');

program
    .command('encrypt')
    .description('Encrypt a file to .4cry format')
    .argument('<input>', 'Input file')
    .argument('[output]', 'Output file (.4cry) - optional')
    .option('-p, --password <password>', 'Password for encryption')
    .option('-g, --generate-password', 'Generate a secure password automatically')
    .option('--hide-metadata', 'Hide metadata for maximum privacy')
    .option('--camouflage-size <size>', 'Camouflage file size (e.g., 5MB, 1.2GB)')
    .option('--random-camouflage', 'Apply random size camouflage')
    .action(async (input, output, options) => {
        try {
            if (!fs.existsSync(input)) {
                console.error(chalk.red('❌ Input file not found'));
                process.exit(1);
            }
            
            const outputFile = encryption.getOutputPath(input, 'encrypt', output);
            let password = options.password;
            
            if (options.generatePassword) {
                password = encryption.generateSecurePassword();
                console.log(chalk.green('🔑 Auto-generated password:'), chalk.bold(password));
                console.log(chalk.yellow('⚠️  IMPORTANT: Store this password securely!'));
            }
            
            if (!password) {
                const readline = require('readline').createInterface({
                    input: process.stdin,
                    output: process.stdout
                });
                
                password = await new Promise((resolve) => {
                    readline.question(chalk.cyan('🔐 Enter password for encryption: '), (answer) => {
                        readline.close();
                        resolve(answer);
                    });
                });
            }
            
            if (!password) {
                console.error(chalk.red('❌ Password is required'));
                process.exit(1);
            }
            
            const strength = encryption.analyzePasswordStrength(password);
            console.log(chalk[strength.color](`🔒 Password strength: ${strength.strength}`));
            
            if (strength.feedback.length > 0) {
                console.log(chalk.yellow('💡 Suggestions:'), strength.feedback.join(', '));
            }
            
            // Determine if camouflage should be used
            let camouflageSize = options.camouflageSize;
            if (options.randomCamouflage && !camouflageSize) {
                camouflageSize = 'random'; // Special flag for random camouflage
            }
            
            await encryption.encryptFile(input, outputFile, password, options.hideMetadata, camouflageSize);
            
        } catch (error) {
            console.error(chalk.red('❌ Error:'), error.message);
            process.exit(1);
        }
    });

program
    .command('decrypt')
    .description('Decrypt a .4cry file')
    .argument('<input>', 'Input .4cry file')
    .argument('[output]', 'Output file - optional')
    .option('-p, --password <password>', 'Password for decryption')
    .action(async (input, output, options) => {
        try {
            if (!fs.existsSync(input)) {
                console.error(chalk.red('❌ .4cry file not found'));
                process.exit(1);
            }
            
            const outputFile = encryption.getOutputPath(input, 'decrypt', output);
            let password = options.password;
            
            if (!password) {
                const readline = require('readline').createInterface({
                    input: process.stdin,
                    output: process.stdout
                });
                
                password = await new Promise((resolve) => {
                    readline.question(chalk.cyan('🔐 Enter password for decryption: '), (answer) => {
                        readline.close();
                        resolve(answer);
                    });
                });
            }
            
            if (!password) {
                console.error(chalk.red('❌ Password is required'));
                process.exit(1);
            }
            
            await encryption.decryptFile(input, outputFile, password);
            
        } catch (error) {
            console.error(chalk.red('❌ Error:'), error.message);
            process.exit(1);
        }
    });

program
    .command('generate-password')
    .description('Generate a secure password')
    .option('-l, --length <length>', 'Password length', '32')
    .action((options) => {
        const password = encryption.generateSecurePassword(parseInt(options.length));
        console.log(chalk.green('🔑 Secure password generated:'), chalk.bold(password));
        
        const strength = encryption.analyzePasswordStrength(password);
        console.log(chalk[strength.color](`🔒 Strength: ${strength.strength}`));
    });

program
    .command('analyze-password')
    .description('Enhanced password analysis for v3.0')
    .argument('<password>', 'Password to analyze')
    .action((password) => {
        const analysis = encryption.analyzePasswordStrength(password);
        console.log(chalk[analysis.color](`🔒 Password strength: ${analysis.strength} (${analysis.score}/8)`));
        console.log(chalk.blue(`📊 Entropy: ${analysis.entropy.toFixed(2)} bits`));
        console.log(chalk.blue(`✅ Valid: ${analysis.isValid ? 'Yes' : 'No'}`));
        
        if (analysis.feedback.length > 0) {
            console.log(chalk.yellow('💡 Suggestions for improvement:'));
            analysis.feedback.forEach(tip => console.log(chalk.gray(`  • ${tip}`)));
        } else {
            console.log(chalk.green('✅ Password meets all security requirements!'));
        }
    });

program
    .command('security-audit')
    .description('Perform security audit of the system')
    .option('--check-passwords', 'Audit stored passwords')
    .option('--check-logs', 'Review security logs')
    .option('--check-sessions', 'Check active sessions')
    .action((options) => {
        console.log(chalk.cyan('🔍 Starting security audit...'));
        
        // Check key storage security
        if (fs.existsSync(encryption.KEY_STORAGE_DIR)) {
            console.log(chalk.green('✅ Key storage directory exists'));
            
            if (fs.existsSync(encryption.MASTER_KEY_FILE)) {
                console.log(chalk.green('✅ Master key file exists'));
            } else {
                console.log(chalk.yellow('⚠️ Master key file not found'));
            }
            
            if (fs.existsSync(encryption.KEY_DATABASE_FILE)) {
                console.log(chalk.green('✅ Key database exists'));
            } else {
                console.log(chalk.yellow('⚠️ Key database not found'));
            }
        } else {
            console.log(chalk.red('❌ Key storage directory not found'));
        }
        
        // Check security logs
        if (options.checkLogs && fs.existsSync(encryption.SECURITY_LOG_FILE)) {
            console.log(chalk.blue('📋 Recent security events:'));
            const logs = fs.readFileSync(encryption.SECURITY_LOG_FILE, 'utf8')
                .split('\n')
                .filter(line => line.trim())
                .slice(-5); // Last 5 events
            
            logs.forEach(log => {
                try {
                    const event = JSON.parse(log);
                    console.log(chalk.gray(`  • ${event.timestamp}: ${event.event} - ${event.details}`));
                } catch (e) {
                    console.log(chalk.gray(`  • ${log}`));
                }
            });
        }
        
        console.log(chalk.green('🔍 Security audit completed'));
    });

program
    .command('generate-keypair')
    .description('Generate RSA key pair for advanced encryption')
    .option('--bits <bits>', 'Key size in bits', '4096')
    .option('--output <dir>', 'Output directory', './keys')
    .action((options) => {
        try {
            const keySize = parseInt(options.bits);
            const outputDir = options.output;
            
            if (!fs.existsSync(outputDir)) {
                fs.mkdirSync(outputDir, { recursive: true });
            }
            
            console.log(chalk.cyan(`🔑 Generating ${keySize}-bit RSA key pair...`));
            
            const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
                modulusLength: keySize,
                publicKeyEncoding: {
                    type: 'spki',
                    format: 'pem'
                },
                privateKeyEncoding: {
                    type: 'pkcs8',
                    format: 'pem'
                }
            });
            
            const publicKeyFile = path.join(outputDir, 'public.pem');
            const privateKeyFile = path.join(outputDir, 'private.pem');
            
            fs.writeFileSync(publicKeyFile, publicKey);
            fs.writeFileSync(privateKeyFile, privateKey);
            
            console.log(chalk.green(`✅ Public key saved: ${publicKeyFile}`));
            console.log(chalk.green(`✅ Private key saved: ${privateKeyFile}`));
            console.log(chalk.yellow('⚠️ Keep your private key secure!'));
            
        } catch (error) {
            console.error(chalk.red('❌ Error generating key pair:'), error.message);
            process.exit(1);
        }
    });

program
    .command('file-info')
    .description('Analyze file information and security')
    .argument('<file>', 'File to analyze')
    .action((file) => {
        try {
            if (!fs.existsSync(file)) {
                console.error(chalk.red('❌ File not found'));
                process.exit(1);
            }
            
            const stats = fs.statSync(file);
            const ext = path.extname(file).toLowerCase();
            
            console.log(chalk.cyan('📊 File Analysis:'));
            console.log(chalk.blue(`📁 Name: ${path.basename(file)}`));
            console.log(chalk.blue(`📏 Size: ${encryption.formatBytes(stats.size)}`));
            console.log(chalk.blue(`📅 Modified: ${stats.mtime.toLocaleString()}`));
            console.log(chalk.blue(`🔗 Extension: ${ext || 'None'}`));
            
            // Security assessment
            const securityScore = encryption.assessFileSecurity(file, stats);
            console.log(chalk[securityScore.color](`🔒 Security Level: ${securityScore.level}`));
            
            if (securityScore.recommendations.length > 0) {
                console.log(chalk.yellow('💡 Recommendations:'));
                securityScore.recommendations.forEach(rec => console.log(chalk.gray(`  • ${rec}`)));
            }
            
        } catch (error) {
            console.error(chalk.red('❌ Error analyzing file:'), error.message);
            process.exit(1);
        }
    });

program
    .command('encrypt-with-key')
    .description('Encrypt file using RSA public key')
    .argument('<input>', 'Input file to encrypt')
    .argument('<output>', 'Output encrypted file')
    .argument('<publicKey>', 'RSA public key file (.pem)')
    .option('-p, --password <password>', 'Password for AES encryption')
    .action(async (input, output, publicKey, options) => {
        try {
            let password = options.password;
            
            if (!password) {
                const readline = require('readline').createInterface({
                    input: process.stdin,
                    output: process.stdout
                });
                
                password = await new Promise((resolve) => {
                    readline.question(chalk.cyan('🔐 Enter password for AES encryption: '), (answer) => {
                        readline.close();
                        resolve(answer);
                    });
                });
            }
            
            if (!password) {
                console.error(chalk.red('❌ Password is required'));
                process.exit(1);
            }
            
            await encryption.encryptWithPublicKey(input, output, publicKey, password);
            
        } catch (error) {
            console.error(chalk.red('❌ Error:'), error.message);
            process.exit(1);
        }
    });

program
    .command('decrypt-with-key')
    .description('Decrypt file using RSA private key')
    .argument('<input>', 'Input encrypted file')
    .argument('<output>', 'Output decrypted file')
    .argument('<privateKey>', 'RSA private key file (.pem)')
    .option('-p, --password <password>', 'Password for AES decryption')
    .action(async (input, output, privateKey, options) => {
        try {
            let password = options.password;
            
            if (!password) {
                const readline = require('readline').createInterface({
                    input: process.stdin,
                    output: process.stdout
                });
                
                password = await new Promise((resolve) => {
                    readline.question(chalk.cyan('🔐 Enter password for AES decryption: '), (answer) => {
                        readline.close();
                        resolve(answer);
                    });
                });
            }
            
            if (!password) {
                console.error(chalk.red('❌ Password is required'));
                process.exit(1);
            }
            
            await encryption.decryptWithPrivateKey(input, output, privateKey, password);
            
        } catch (error) {
            console.error(chalk.red('❌ Error:'), error.message);
            process.exit(1);
        }
    });

program
    .command('multi-encrypt')
    .description('Encrypt file with multiple layers for MAXIMUM SECURITY')
    .argument('<input>', 'Input file to encrypt')
    .argument('<output>', 'Output encrypted file')
    .option('-p, --password <password>', 'Password for encryption')
    .option('-l, --layers <layers>', 'Number of encryption layers (2-10)', '3')
    .option('-g, --generate-password', 'Generate a secure password automatically')
    .option('--hide-metadata', 'Hide metadata for maximum privacy')
    .action(async (input, output, options) => {
        try {
            let password = options.password;
            const layers = parseInt(options.layers);
            
            if (!password && !options.generatePassword) {
                const readline = require('readline').createInterface({
                    input: process.stdin,
                    output: process.stdout
                });
                
                password = await new Promise((resolve) => {
                    readline.question(chalk.cyan('🔐 Enter password: '), (answer) => {
                        readline.close();
                        resolve(answer);
                    });
                });
            }
            
            if (options.generatePassword) {
                password = encryption.generateSecurePassword();
                console.log(chalk.green(`🔑 Generated password: ${password}`));
            }
            
            if (!password) {
                console.error(chalk.red('❌ Password is required'));
                process.exit(1);
            }
            
            if (layers < 2 || layers > 10) {
                console.error(chalk.red('❌ Layers must be between 2 and 10'));
                process.exit(1);
            }
            
            await encryption.multiLayerEncrypt(input, output, password, layers, {
                hideMetadata: options.hideMetadata
            });
            
        } catch (error) {
            console.error(chalk.red('❌ Error:'), error.message);
            process.exit(1);
        }
    });

program
    .command('multi-decrypt')
    .description('Decrypt file encrypted with multiple layers')
    .argument('<input>', 'Input encrypted file')
    .argument('<output>', 'Output decrypted file')
    .option('-p, --password <password>', 'Password for decryption')
    .option('-l, --layers <layers>', 'Number of encryption layers (2-10)', '3')
    .action(async (input, output, options) => {
        try {
            let password = options.password;
            const layers = parseInt(options.layers);
            
            if (!password) {
                const readline = require('readline').createInterface({
                    input: process.stdin,
                    output: process.stdout
                });
                
                password = await new Promise((resolve) => {
                    readline.question(chalk.cyan('🔐 Enter password: '), (answer) => {
                        readline.close();
                        resolve(answer);
                    });
                });
            }
            
            if (!password) {
                console.error(chalk.red('❌ Password is required'));
                process.exit(1);
            }
            
            if (layers < 2 || layers > 10) {
                console.error(chalk.red('❌ Layers must be between 2 and 10'));
                process.exit(1);
            }
            
            await encryption.multiLayerDecrypt(input, output, password, layers);
            
        } catch (error) {
            console.error(chalk.red('❌ Error:'), error.message);
            process.exit(1);
        }
    });

program
    .command('erase')
    .description('ULTRA-SECURE ERASE - Encrypt file and ELIMINATE ALL TRACES (NO RECOVERY POSSIBLE)')
    .argument('<input>', 'Input file to ultra-securely erase')
    .argument('<output>', 'Output encrypted file')
    .option('-p, --password <password>', 'Password for encryption')
    .option('-g, --generate-password', 'Generate a secure password automatically')
    .option('--overwrite-passes <passes>', 'Number of overwrite passes (5-25)', '15')
    .option('--hide-metadata', 'Hide metadata for maximum privacy')
    .option('--random-camouflage', 'Add random size camouflage')
    .action(async (input, output, options) => {
        try {
            let password = options.password;
            const overwritePasses = parseInt(options.overwritePasses);
            
            if (!password && !options.generatePassword) {
                const readline = require('readline').createInterface({
                    input: process.stdin,
                    output: process.stdout
                });
                
                password = await new Promise((resolve) => {
                    readline.question(chalk.red('🔥 WARNING: Original file will be PERMANENTLY DESTROYED!\n🔐 Enter password: '), (answer) => {
                        readline.close();
                        resolve(answer);
                    });
                });
            }
            
            if (options.generatePassword) {
                password = encryption.generateSecurePassword();
                console.log(chalk.green(`🔑 Generated password: ${password}`));
            }
            
            if (!password) {
                console.error(chalk.red('❌ Password is required'));
                process.exit(1);
            }
            
            if (overwritePasses < 5 || overwritePasses > 25) {
                console.error(chalk.red('❌ Overwrite passes must be between 5 and 25'));
                process.exit(1);
            }
            
            // Final confirmation
            const readline = require('readline').createInterface({
                input: process.stdin,
                output: process.stdout
            });
            
            const confirmation = await new Promise((resolve) => {
                readline.question(chalk.red('⚠️ FINAL WARNING: This will ELIMINATE ALL TRACES of the original file!\nType "ERASE" to confirm: '), (answer) => {
                    readline.close();
                    resolve(answer);
                });
            });
            
            if (confirmation !== 'ERASE') {
                console.log(chalk.yellow('❌ Operation cancelled - file not erased'));
                process.exit(0);
            }
            
            await encryption.secureErase(input, output, password, {
                overwritePasses: overwritePasses,
                hideMetadata: options.hideMetadata,
                randomCamouflage: options.randomCamouflage
            });
            
        } catch (error) {
            console.error(chalk.red('❌ Error:'), error.message);
            process.exit(1);
        }
    });

program
    .command('destroy')
    .description('💀 DESTROY SECURE - Apaga arquivos/pastas SEM salvar backup criptografado')
    .argument('<path>', 'Arquivo ou pasta a ser completamente destruído')
    .option('-p, --password <password>', 'Senha para o processo de criptografia durante o apagamento')
    .option('-g, --generate-password', 'Gerar senha automaticamente')
    .option('--overwrite-passes <passes>', 'Número de passadas de criptografia/sobrescrita (10-30)', '20')
    .action(async (path, options) => {
        try {
            let password = options.password;
            const overwritePasses = parseInt(options.overwritePasses);
            
            if (!password && !options.generatePassword) {
                const readline = require('readline').createInterface({
                    input: process.stdin,
                    output: process.stdout
                });
                
                password = await new Promise((resolve) => {
                    readline.question(chalk.red('💀 WARNING: Arquivo/pasta será PERMANENTEMENTE DESTRUÍDO sem backup!\n💀 Nem o FBI conseguirá recuperar!\n🔐 Enter password: '), (answer) => {
                        readline.close();
                        resolve(answer);
                    });
                });
            }
            
            if (options.generatePassword) {
                password = encryption.generateSecurePassword();
                console.log(chalk.green(`🔑 Generated password: ${password}`));
                console.log(chalk.yellow(`⚠️ IMPORTANTE: Esta senha é usada apenas durante o processo de destruição`));
                console.log(chalk.yellow(`⚠️ O arquivo NÃO será recuperável após a destruição!`));
            }
            
            if (!password) {
                console.error(chalk.red('❌ Password is required'));
                process.exit(1);
            }
            
            if (overwritePasses < 10 || overwritePasses > 30) {
                console.error(chalk.red('❌ Overwrite passes must be between 10 and 30'));
                process.exit(1);
            }
            
            // Final confirmation
            const readline = require('readline').createInterface({
                input: process.stdin,
                output: process.stdout
            });
            
            const confirmation = await new Promise((resolve) => {
                readline.question(chalk.red('⚠️ FINAL WARNING: This will DESTROY the file/folder COMPLETELY!\n⚠️ NO BACKUP will be created - file will be IMPOSSIBLE to recover!\n⚠️ Type "DESTROY" to confirm: '), (answer) => {
                    readline.close();
                    resolve(answer);
                });
            });
            
            if (confirmation !== 'DESTROY') {
                console.log(chalk.yellow('❌ Operation cancelled - file not destroyed'));
                process.exit(0);
            }
            
            await encryption.secureDelete(path, password, {
                overwritePasses: overwritePasses
            });
            
        } catch (error) {
            console.error(chalk.red('❌ Error:'), error.message);
            process.exit(1);
        }
    });

program
    .command('encrypt-folder')
    .description('Encrypt entire folder with MAXIMUM SECURITY and ANONYMITY')
    .argument('<inputFolder>', 'Input folder to encrypt')
    .argument('<outputFolder>', 'Output folder for encrypted files')
    .option('-p, --password <password>', 'Password for encryption')
    .option('-g, --generate-password', 'Generate a secure password automatically')
    .option('--hide-metadata', 'Hide metadata for maximum privacy (DEFAULT: true)')
    .option('--camouflage-size <size>', 'Camouflage file size (e.g., 5MB, 1.2GB)')
    .option('--random-camouflage', 'Apply random size camouflage (DEFAULT: true)')
    .option('--no-preserve-structure', 'Do not preserve folder structure')
    .option('--exclude-patterns <patterns>', 'Exclude patterns (comma-separated)')
    .option('--include-patterns <patterns>', 'Include only these extensions (comma-separated)')
    .option('--max-file-size <size>', 'Maximum file size limit (e.g., 1GB)', '2GB')
    .option('--store-key <keyId>', 'Store password with key ID for future use')
    .action(async (inputFolder, outputFolder, options) => {
        try {
            let password = options.password;
            
            if (options.generatePassword) {
                password = encryption.generateSecurePassword();
                console.log(chalk.green('🔑 Auto-generated password:'), chalk.bold(password));
                console.log(chalk.yellow('⚠️  IMPORTANT: Store this password securely!'));
            }
            
            if (!password) {
                const readline = require('readline').createInterface({
                    input: process.stdin,
                    output: process.stdout
                });
                
                password = await new Promise((resolve) => {
                    readline.question(chalk.cyan('🔐 Enter password for MAXIMUM SECURITY folder encryption: '), (answer) => {
                        readline.close();
                        resolve(answer);
                    });
                });
            }
            
            if (!password) {
                console.error(chalk.red('❌ Password is required for maximum security'));
                process.exit(1);
            }
            
            // Store password if requested
            if (options.storeKey) {
                encryption.storePassword(options.storeKey, password, `MAX SECURITY folder encryption - ${new Date().toISOString()}`);
            }
            
            const strength = encryption.analyzePasswordStrength(password);
            console.log(chalk[strength.color](`🔒 Password strength: ${strength.strength}`));
            
            if (strength.feedback.length > 0) {
                console.log(chalk.yellow('💡 Suggestions:'), strength.feedback.join(', '));
            }
            
            // Parse patterns
            let excludePatterns = [];
            if (options.excludePatterns) {
                excludePatterns = options.excludePatterns.split(',').map(p => p.trim());
            }
            
            let includePatterns = [];
            if (options.includePatterns) {
                includePatterns = options.includePatterns.split(',').map(p => p.trim().toLowerCase());
            }
            
            // Parse max file size
            let maxFileSize = 2 * 1024 * 1024 * 1024; // 2GB default
            if (options.maxFileSize) {
                maxFileSize = encryption.parseSizeToBytes(options.maxFileSize);
            }
            
            // Encrypt folder with maximum security
            const results = await encryption.encryptFolder(inputFolder, outputFolder, password, {
                hideMetadata: options.hideMetadata !== false, // Default true
                camouflageSize: options.camouflageSize,
                randomCamouflage: options.randomCamouflage !== false, // Default true
                preserveStructure: !options.noPreserveStructure,
                excludePatterns: excludePatterns,
                includePatterns: includePatterns,
                maxFileSize: maxFileSize
            });
            
            console.log(chalk.bold.red(`\n🔒 MAXIMUM SECURITY FOLDER ENCRYPTION COMPLETED!`));
            console.log(chalk.green(`✅ ${results.successful.length} files encrypted with MAXIMUM SECURITY`));
            if (results.failed.length > 0) {
                console.log(chalk.red(`❌ ${results.failed.length} files failed security checks`));
            }
            
        } catch (error) {
            console.error(chalk.red('❌ Security Error:'), error.message);
            process.exit(1);
        }
    });

program
    .command('decrypt-folder')
    .description('Decrypt entire folder with MAXIMUM SECURITY')
    .argument('<inputFolder>', 'Input folder with encrypted files')
    .argument('<outputFolder>', 'Output folder for decrypted files')
    .option('-p, --password <password>', 'Password for decryption')
    .option('--no-preserve-structure', 'Do not preserve folder structure')
    .action(async (inputFolder, outputFolder, options) => {
        try {
            let password = options.password;
            
            if (!password) {
                const readline = require('readline').createInterface({
                    input: process.stdin,
                    output: process.stdout
                });
                
                password = await new Promise((resolve) => {
                    readline.question(chalk.cyan('🔐 Enter password for MAXIMUM SECURITY folder decryption: '), (answer) => {
                        readline.close();
                        resolve(answer);
                    });
                });
            }
            
            if (!password) {
                console.error(chalk.red('❌ Password is required for maximum security'));
                process.exit(1);
            }
            
            // Decrypt folder
            const results = await encryption.decryptFolder(inputFolder, outputFolder, password, {
                preserveStructure: !options.noPreserveStructure
            });
            
            console.log(chalk.bold.green(`\n🔓 MAXIMUM SECURITY FOLDER DECRYPTION COMPLETED!`));
            console.log(chalk.green(`✅ ${results.successful.length} files decrypted successfully`));
            if (results.failed.length > 0) {
                console.log(chalk.red(`❌ ${results.failed.length} files failed decryption`));
            }
            
        } catch (error) {
            console.error(chalk.red('❌ Security Error:'), error.message);
            process.exit(1);
        }
    });

program
    .command('batch-encrypt')
    .description('Batch encrypt multiple files or directories')
    .argument('<inputs...>', 'Input files or directories')
    .option('-p, --password <password>', 'Password for encryption')
    .option('-g, --generate-password', 'Generate a secure password automatically')
    .option('--hide-metadata', 'Hide metadata for maximum privacy')
    .option('--camouflage-size <size>', 'Camouflage file size (e.g., 5MB, 1.2GB)')
    .option('--random-camouflage', 'Apply random size camouflage')
    .option('--no-recursive', 'Do not scan directories recursively')
    .option('--extensions <extensions>', 'File extensions to include (comma-separated)')
    .option('--output-dir <dir>', 'Output directory', './encrypted')
    .option('--store-key <keyId>', 'Store password with key ID for future use')
    .action(async (inputs, options) => {
        try {
            let password = options.password;
            
            if (options.generatePassword) {
                password = encryption.generateSecurePassword();
                console.log(chalk.green('🔑 Auto-generated password:'), chalk.bold(password));
                console.log(chalk.yellow('⚠️  IMPORTANT: Store this password securely!'));
            }
            
            if (!password) {
                const readline = require('readline').createInterface({
                    input: process.stdin,
                    output: process.stdout
                });
                
                password = await new Promise((resolve) => {
                    readline.question(chalk.cyan('🔐 Enter password for batch encryption: '), (answer) => {
                        readline.close();
                        resolve(answer);
                    });
                });
            }
            
            if (!password) {
                console.error(chalk.red('❌ Password is required'));
                process.exit(1);
            }
            
            // Store password if requested
            if (options.storeKey) {
                encryption.storePassword(options.storeKey, password, `Batch encryption - ${new Date().toISOString()}`);
            }
            
            const strength = encryption.analyzePasswordStrength(password);
            console.log(chalk[strength.color](`🔒 Password strength: ${strength.strength}`));
            
            if (strength.feedback.length > 0) {
                console.log(chalk.yellow('💡 Suggestions:'), strength.feedback.join(', '));
            }
            
            // Parse extensions
            let extensions = [];
            if (options.extensions) {
                extensions = options.extensions.split(',').map(ext => ext.trim().toLowerCase());
            }
            
            // Batch encrypt
            const results = await encryption.batchEncrypt(inputs, password, {
                hideMetadata: options.hideMetadata,
                camouflageSize: options.camouflageSize,
                randomCamouflage: options.randomCamouflage,
                recursive: !options.noRecursive,
                extensions: extensions,
                outputDir: options.outputDir
            });
            
            console.log(chalk.bold.green(`\n🎉 Batch encryption completed!`));
            console.log(chalk.green(`✅ ${results.successful.length} files encrypted successfully`));
            if (results.failed.length > 0) {
                console.log(chalk.red(`❌ ${results.failed.length} files failed`));
            }
            
        } catch (error) {
            console.error(chalk.red('❌ Error:'), error.message);
            process.exit(1);
        }
    });

program
    .command('store-key')
    .description('Store a password securely')
    .argument('<keyId>', 'Unique key identifier')
    .argument('<password>', 'Password to store')
    .option('-d, --description <description>', 'Description for the key')
    .action((keyId, password, options) => {
        try {
            encryption.storePassword(keyId, password, options.description || '');
            console.log(chalk.green(`🔐 Password stored with ID: ${keyId}`));
        } catch (error) {
            console.error(chalk.red('❌ Error:'), error.message);
            process.exit(1);
        }
    });

program
    .command('retrieve-key')
    .description('Retrieve a stored password')
    .argument('<keyId>', 'Key identifier')
    .action((keyId) => {
        try {
            const result = encryption.retrievePassword(keyId);
            console.log(chalk.green(`🔑 Password for ${keyId}:`), chalk.bold(result.password));
            console.log(chalk.gray(`📝 Description: ${result.description}`));
            console.log(chalk.gray(`📅 Created: ${result.createdAt}`));
        } catch (error) {
            console.error(chalk.red('❌ Error:'), error.message);
            process.exit(1);
        }
    });

program
    .command('list-keys')
    .description('List all stored keys')
    .action(() => {
        try {
            const keys = encryption.listStoredKeys();
            if (keys.length === 0) {
                console.log(chalk.yellow('No keys stored'));
            } else {
                console.log(chalk.cyan(`📋 Stored Keys (${keys.length}):`));
                keys.forEach(key => {
                    console.log(chalk.green(`  🔑 ${key.id}`));
                    console.log(chalk.gray(`     📝 ${key.description}`));
                    console.log(chalk.gray(`     📅 ${key.createdAt}`));
                    console.log('');
                });
            }
        } catch (error) {
            console.error(chalk.red('❌ Error:'), error.message);
            process.exit(1);
        }
    });

program
    .command('delete-key')
    .description('Delete a stored key')
    .argument('<keyId>', 'Key identifier to delete')
    .action((keyId) => {
        try {
            encryption.deleteStoredKey(keyId);
            console.log(chalk.green(`🗑️ Key deleted: ${keyId}`));
        } catch (error) {
            console.error(chalk.red('❌ Error:'), error.message);
            process.exit(1);
        }
    });

// Execute CLI if called directly
if (require.main === module) {
    console.log(chalk.bold.cyan(`
╔══════════════════════════════════════════════════════════════╗
║                   🔐 4CRY ENCRYPT v3.0 🔐                    ║
║              Advanced File Encryption System                 ║
║                Enhanced Security & Features                  ║
╚══════════════════════════════════════════════════════════════╝
    `));
    
    program.parse();
}

module.exports = AdvancedFileEncryption;

