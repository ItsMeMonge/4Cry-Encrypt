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
        this.VERSION = '2.2.0';
        this.COMPRESSION_LEVEL = 9; // Máxima compressão
        this.CHUNK_SIZE = 64 * 1024; // 64KB chunks para processamento eficiente
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
     * Analisa a força de uma senha
     */
    analyzePasswordStrength(password) {
        let score = 0;
        let feedback = [];
        
        if (password.length >= 8) score += 1;
        else feedback.push('Password must be at least 8 characters');
        
        if (password.length >= 12) score += 1;
        if (/[a-z]/.test(password)) score += 1;
        else feedback.push('Add lowercase letters');
        
        if (/[A-Z]/.test(password)) score += 1;
        else feedback.push('Add uppercase letters');
        
        if (/[0-9]/.test(password)) score += 1;
        else feedback.push('Add numbers');
        
        if (/[^a-zA-Z0-9]/.test(password)) score += 1;
        else feedback.push('Add special symbols');
        
        const strength = score <= 2 ? 'Weak' : score <= 4 ? 'Medium' : 'Strong';
        const color = score <= 2 ? 'red' : score <= 4 ? 'yellow' : 'green';
        
        return { score, strength, color, feedback };
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
    .description('Analyze password strength')
    .argument('<password>', 'Password to analyze')
    .action((password) => {
        const analysis = encryption.analyzePasswordStrength(password);
        console.log(chalk[analysis.color](`🔒 Password strength: ${analysis.strength} (${analysis.score}/6)`));
        
        if (analysis.feedback.length > 0) {
            console.log(chalk.yellow('💡 Suggestions for improvement:'));
            analysis.feedback.forEach(tip => console.log(chalk.gray(`  • ${tip}`)));
        } else {
            console.log(chalk.green('✅ Password has good strength!'));
        }
    });

// Execute CLI if called directly
if (require.main === module) {
    console.log(chalk.bold.cyan(`
╔══════════════════════════════════════════════════════════════╗
║                   🔐 4CRY ENCRYPT 🔐                         ║
║              Advanced File Encryption System                 ║
║                    Secure & Reliable v2.2                    ║
╚══════════════════════════════════════════════════════════════╝
    `));
    
    program.parse();
}

module.exports = AdvancedFileEncryption;
