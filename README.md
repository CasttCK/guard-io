# 🛡️ GuardIO - Verificador de Segurança de Sites

**GuardIO** é uma aplicação web desenvolvida em Flask que permite verificar a confiabilidade e segurança de sites e lojas online. A ferramenta analisa URLs através de múltiplos critérios de segurança, incluindo verificação com VirusTotal, análise de domínios confiáveis e detecção de características suspeitas.

## ✨ Funcionalidades

- 🔍 **Verificação de URLs em tempo real**
- 🛡️ **Integração com VirusTotal API** para detecção de malware
- 📊 **Lista de domínios confiáveis** baseada no ranking Tranco
- 🔒 **Verificação de HTTPS**
- ⚠️ **Detecção de características suspeitas**:
  - URLs muito longas
  - Domínios com hífens
  - Caracteres não-ASCII (possível homografia)
- 📈 **Sistema de pontuação** de 0 a 100 pontos

## 🚀 Tecnologias Utilizadas

- **Backend**: Flask 3.1.2
- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **APIs**: VirusTotal API v3
- **Bibliotecas Python**:
  - `pandas` - Manipulação de dados
  - `tldextract` - Extração de domínios
  - `validators` - Validação de URLs
  - `requests` - Requisições HTTP
  - `python-dotenv` - Gerenciamento de variáveis de ambiente

## 📋 Pré-requisitos

- Python 3.7+
- Chave da API do VirusTotal (gratuita)
- Git (para clonagem do repositório)

## 🔧 Instalação

1. **Clone o repositório**:
```bash
git clone https://github.com/CasttCK/guard-io.git
cd guard-io
```

2. **Crie um ambiente virtual**:
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

3. **Instale as dependências**:
```bash
pip install -r requirements.txt
```

4. **Configure as variáveis de ambiente**:
```bash
# Crie um arquivo .env na raiz do projeto
echo "VIRUS_TOTAL_API_KEY=sua_chave_api_aqui" > .env
```

## ⚙️ Configuração

### Obtenha sua chave da API do VirusTotal:

1. Acesse [VirusTotal](https://www.virustotal.com/)
2. Crie uma conta gratuita
3. Vá em **Perfil** → **API Key**
4. Copie sua chave e adicione no arquivo `.env`

### Arquivo `.env` de exemplo:
```env
VIRUS_TOTAL_API_KEY=0123456789abcdef0123456789abcdef01234567
```

## 🖥️ Como Usar

1. **Inicie a aplicação**:
```bash
python app.py
```

2. **Acesse no navegador**:
```
http://localhost:5000
```

3. **Digite uma URL** no campo de busca e clique no botão de verificação

4. **Visualize o resultado** com:
   - Status de segurança (Confiável/Atenção/Suspeito)
   - Pontuação de 0 a 100
   - Lista detalhada de problemas encontrados

## 📡 API Endpoints

### POST `/check_url`

Verifica a segurança de uma URL.

**Request Body**:
```json
{
  "url": "https://exemplo.com"
}
```

**Response**:
```json
{
  "url": "https://exemplo.com",
  "domain": "exemplo.com",
  "score": 90,
  "status": "reliable",
  "issues": []
}
```
## 🔍 Sistema de Pontuação

A pontuação é calculada baseada nos seguintes critérios:

| Critério | Pontos | Descrição |
|----------|--------|-----------|
| HTTPS | +20 | URL utiliza protocolo seguro |
| Domínio Confiável | +30 | Domínio presente no ranking Tranco |
| URL Curta | +10 | URL com menos de 100 caracteres |
| VirusTotal Limpo | +40 | Nenhuma detecção de malware |

**Penalizações**:
- Domínio com hífen: Suspeito
- Caracteres não-ASCII: Possível ataque homográfico
- Detecção no VirusTotal: Pontuação zerada

**Status possíveis**:
- `reliable` - Confiável (80+ pontos, sem problemas)
- `acceptable` - Aceitável (60+ pontos, poucos problemas)
- `suspect` - Suspeito (< 60 pontos ou problemas críticos)
- `invalid` - URL inválida

## 📁 Estrutura do Projeto

```
guard-io/
├── app.py                      # Aplicação principal Flask
├── requirements.txt            # Dependências Python
├── tranco_list.csv             # Lista de domínios confiáveis
├── .env                        # Variáveis de ambiente (não versionado)
├── templates/
│   └── index.html              # Interface principal
├── assets/
│   ├── icons/
│   │   └── favicon.ico         # Ícone da aplicação
│   └── images/
│       └── logo_guard_io.png   # Logo do GuardIO
└── README.md                   # Este arquivo
```

## 🤝 Contribuição

1. Faça um fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 🔄 Possíveis Atualizações Futuras

- [ ] Verificação de certificados SSL
- [ ] Análise de reputação de domínios

