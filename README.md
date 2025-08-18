# 😭 4CRY ENCRYPT v2.2 - "For Cry" Secure & Reliable System

Sistema avançado de criptografia seguro e confiável! Converte qualquer arquivo para `.4cry` com compressão moderada, múltiplas camadas de segurança e máxima compatibilidade com arquivos binários como PDFs.

## 🚀 Características Avançadas

### 🔒 Múltiplas Camadas de Criptografia
- **AES-256-GCM**: Criptografia simétrica de nível militar com autenticação
- **PBKDF2**: Derivação segura de chaves com 100.000 iterações
- **HMAC-SHA256**: Verificação de integridade dos dados
- **Tag de Autenticação**: Proteção contra manipulação de dados

### 🛡️ Recursos de Segurança v2.2
- **🗜️ Compressão Segura**: Deflate ou Gzip (nível 6) para máxima compatibilidade
- **✅ PDF/Binário Safe**: Sem pré-processamento que corrompe arquivos
- **🔒 100% Integridade**: Preserva todos os dados originais
- **Steganografia de Metadados**: Oculta informações do arquivo original
- **Verificação de Integridade**: Detecta qualquer alteração nos dados
- **Salt Único**: Cada arquivo usa salt diferente

### 🎯 Funcionalidades "For Cry" v2.2
- Conversão de qualquer tipo de arquivo para formato `.4cry`
- **📄 PDFs Seguros**: Funciona perfeitamente com arquivos binários
- **🗜️ Compressão Moderada**: ~20-30% redução sem riscos
- **📁 Organização Automática**: Pastas `input/`, `output/`, `encrypted/`, `decrypted/`
- **🛡️ Máxima Confiabilidade**: Sistema simplificado e robusto
- Descriptografia completa com restauração do arquivo original
- Análise de força de senha
- Geração automática de senhas seguras
- Interface CLI com emojis divertidos 😭
- Preservação total de metadados originais

## 📦 Instalação

```bash
# Clone o projeto
git clone https://github.com/ItsMeMonge/4Cry-Encrypt.git
cd 4Cry-Encrypt

# Instale as dependências
npm install

# Torne o script executável (Linux/Mac)
chmod +x 4cry.js
```

## 🎮 Como Usar

### Criptografar um Arquivo

```bash
# Criptografia com senha manual (salva em ./encrypted/)
node 4cry.js encrypt minha_imagem.jpg

# Criptografia com senha especificada
node 4cry.js encrypt documento.pdf -p "minha_senha_super_segura"

# Gerar senha automática (mais seguro)
node 4cry.js encrypt video.mp4 --generate-password

# Especificar arquivo de saída customizado
node 4cry.js encrypt arquivo.txt ./custom/path/arquivo.4cry
```

### Descriptografar um Arquivo

```bash
# Descriptografia com prompt de senha (salva em ./decrypted/)
node 4cry.js decrypt ./encrypted/arquivo.4cry

# Descriptografia com senha especificada
node 4cry.js decrypt ./encrypted/arquivo.4cry -p "minha_senha_super_segura"

# Especificar arquivo de saída customizado
node 4cry.js decrypt ./encrypted/arquivo.4cry ./restored/arquivo_original.jpg
```

### Utilitários de Senha

```bash
# Gerar senha segura
node 4cry.js generate-password

# Gerar senha com tamanho específico
node 4cry.js generate-password --length 64

# Analisar força de uma senha
node 4cry.js analyze-password "minha_senha123"
```

## 🔍 Exemplo Prático

```bash
# 1. Criptografar uma imagem
node 4cry.js encrypt foto_secreta.jpg

  # O sistema pedirá uma senha e criará foto_secreta.jpg.4cry

  # 2. Descriptografar a imagem
node 4cry.js decrypt ./encrypted/foto_secreta.jpg.4cry

  # O sistema pedirá a senha e restaurará a imagem original
```

## 🏗️ Estrutura do Arquivo .4cry

```
┌─────────────────────────┐
│ Assinatura "4CRY_v2.0"  │ (9 bytes)
├─────────────────────────┤
│ Header 4CRY v2.2        │ (256 bytes)
├─────────────────────────┤
│ Salt Criptográfico      │ (32 bytes)
├─────────────────────────┤
│ IV AES-256-GCM          │ (16 bytes)
├─────────────────────────┤
│ Auth Tag GCM            │ (16 bytes)
├─────────────────────────┤
│ HMAC de Integridade     │ (32 bytes)
├─────────────────────────┤
│ Chave HMAC              │ (32 bytes)
├─────────────────────────┤
│ Metadados Seguros       │ (variável)
├─────────────────────────┤
│ Dados Criptografados    │ (variável)
└─────────────────────────┘
```

## 🔐 Algoritmos de Segurança Utilizados

| Componente | Algoritmo | Tamanho da Chave | Propósito |
|------------|-----------|------------------|-----------|
| Criptografia Simétrica | AES-256-GCM | 256 bits | Criptografia principal |
| Derivação de Chave | PBKDF2-SHA256 | 256 bits | Derivar chave da senha |
| Verificação de Integridade | HMAC-SHA256 | 256 bits | Detectar alterações |
| Compressão | Deflate/Gzip | N/A | Reduzir tamanho (nível 6) |
| Números Aleatórios | crypto.randomBytes | N/A | Salt, IV, padding |

## ⚠️ Considerações de Segurança v2.2

1. **Senhas Fortes**: Use senhas com pelo menos 12 caracteres, incluindo maiúsculas, minúsculas, números e símbolos
2. **Backup de Senhas**: Guarde as senhas em local seguro - sem elas os arquivos são irrecuperáveis
3. **Arquivos Sensíveis**: Para dados extremamente sensíveis, considere usar o gerador de senhas automático
4. **Verificação de Integridade**: O sistema detecta automaticamente arquivos corrompidos ou modificados
5. **📄 PDFs Seguros**: Versão 2.2 garante compatibilidade total com arquivos binários

## 🚧 Limitações Atuais

- Arquivos muito grandes (>2GB) podem exigir mais memória RAM
- A descriptografia requer a senha exata usada na criptografia
- Não há recuperação de senha - mantenha-as seguras
- Compressão moderada (~20-30%) priorizando segurança sobre tamanho

## 🆕 Novidades v2.2 - "Secure & Reliable"

### ✅ Correções Importantes:
- **🔧 PDF Fix**: Corrigido problema que corrompia arquivos PDF e binários
- **🗜️ Compressão Simplificada**: Removida ultra-compressão agressiva
- **🛡️ Máxima Compatibilidade**: Sistema agora funciona com 100% dos tipos de arquivo
- **⚡ Performance**: Mais rápido e estável
- **🎯 Foco na Segurança**: Prioriza integridade sobre compressão extrema

### 🔄 Diferenças da v2.1:
| Aspecto | v2.1 (Ultra) | v2.2 (Secure) |
|---------|-------------|---------------|
| Compressão | 50-70% | 20-30% |
| PDFs | ❌ Corrompiam | ✅ Funcionam |
| Complexidade | Alta | Simples |
| Confiabilidade | Média | Alta |
| Velocidade | Lenta | Rápida |

## ❓ FAQ - Perguntas Frequentes

### 🤔 Por que meus PDFs não funcionavam na v2.1?
A versão 2.1 tinha pré-processamento agressivo que modificava dados binários. A v2.2 remove isso completamente.

### 📊 Por que a compressão diminuiu?
Priorizamos **integridade** sobre compressão extrema. É melhor ter 20% de redução segura que 70% com risco de corrupção.

### 🔐 Os arquivos ainda são seguros?
**Sim!** A segurança AES-256-GCM permanece inalterada. Apenas simplificamos a compressão.

### 🚀 Qual a diferença do "For Cry" original?
- **Original**: Nome engraçado, ultra-compressão 
- **v2.2**: Nome engraçado, **funcionamento real** 😭

### 📄 Posso usar com qualquer tipo de arquivo?
**Sim!** PDFs, imagens, vídeos, executáveis - todos funcionam perfeitamente na v2.2.

## 🔮 Próximas Versões

- [ ] Interface gráfica (GUI)
- [ ] Criptografia de múltiplos arquivos
- [ ] Armazenamento seguro de chaves
- [ ] Modo de criptografia em lote
- [ ] Suporte a pastas completas

## 📄 Licença

Este projeto está licenciado sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.

---

**4CRY ENCRYPT v2.2** - "For Cry, but now it actually works!" 😭🚀

*Desenvolvido por ItsMeMonge* 💻
