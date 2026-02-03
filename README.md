# Network Tools Suite - Ferramenta de Segurança em Rede

Ferramenta integrada para análise de segurança em rede, com suporte para:
- Varrimento SYN (SYN Scan)
- Ataque UDP Flood
- Análise de logs de segurança (SSH, HTTP)
- Geolocalização de IPs
- Relatórios em PDF
- Gráficos com matplotlib
- Base de dados SQLite

## Instalação

```bash
pip install -r requirements.txt
```

### Dependências do Sistema (Linux/Kali)

Para SSH logs:
```bash
apt-get install openssh-server
```

Para HTTP logs (Apache):
```bash
apt-get install apache2
```

## Uso

### Interface Gráfica

```bash
sudo python3 NetworkToolsGUI.py
```

### Linha de Comando (Log Analyzer)

Analisar logs com GeoIP e base de dados:
```bash
python3 log_analyzer_cli.py --analyze --geoip --db
```

Exportar para CSV:
```bash
python3 log_analyzer_cli.py --analyze --export-csv logs.csv
```

Gerar relatório PDF:
```bash
python3 log_analyzer_cli.py --analyze --db --export-pdf report.pdf
```

Gerar gráficos:
```bash
python3 log_analyzer_cli.py --analyze --db --graphics all
```

Ver ajuda completa:
```bash
python3 log_analyzer_cli.py --help
```

## Funcionalidades

### SYN Scan
- Varrimento de portos com flag SYN
- Interface gráfica para configuração
- Requisitos: `sudo` (privilégios root)

### UDP Flood
- Envio de pacotes UDP para teste de carga
- Confirmação de segurança
- Requisitos: `sudo` (privilégios root)

### Log Analyzer
- Parse automático de logs SSH e HTTP
- Geolocalização de IPs (com fallback)
- Armazenamento em SQLite
- Exportação em CSV e PDF
- Gráficos estatísticos

#### Estatísticas Disponíveis
- Tentativas por serviço
- Tentativas por tipo de evento
- Top IPs com mais tentativas
- Top países com mais tentativas
- Tentativas bem-sucedidas vs falhadas

#### Relatórios PDF
- Estatísticas gerais
- Tabelas de dados
- Top IPs e países

#### Gráficos
- Gráficos de barras por serviço
- Gráficos por tipo de evento
- Distribuição por país
- Distribuição por IP
- Gráficos tipo pizza

## Estrutura do Projeto

```
/
├── NetworkToolsGUI.py           # Interface gráfica principal
├── log_analyzer_cli.py          # Interface de linha de comando
├── SynScan.py                   # Módulo de SYN scan
├── UdpFlood.py                  # Módulo de UDP flood
├── log_analyzer/
│   ├── __init__.py
│   ├── log_parser.py            # Parser de logs SSH/HTTP
│   ├── geoip.py                 # Localização geográfica de IPs
│   ├── database.py              # Base de dados SQLite
│   ├── export.py                # Exportação CSV/PDF
│   └── graphics.py              # Gráficos matplotlib
└── requirements.txt             # Dependências Python
```

## Exemplos de Uso

### Análise Completa de Logs

```bash
# 1. Analisar logs com GeoIP
python3 log_analyzer_cli.py --analyze --geoip --db

# 2. Exportar para CSV
python3 log_analyzer_cli.py --export-csv log_analysis.csv

# 3. Gerar PDF com relatório
python3 log_analyzer_cli.py --export-pdf security_report.pdf

# 4. Gerar gráficos
python3 log_analyzer_cli.py --graphics all

# 5. Ver estatísticas
python3 log_analyzer_cli.py --stats
```

### Via Interface Gráfica

1. Abrir `NetworkToolsGUI.py`
2. Ir até à aba "Log Analyzer"
3. Clicar em "Analisar Logs"
4. Usar os botões para exportar CSV/PDF ou gerar gráficos

## Base de Dados

A base de dados SQLite contém:

### Tabela `log_entries`
- Timestamp
- Serviço (SSH, HTTP)
- IP origem
- Utilizador
- Tipo de evento
- Porto/Status
- Localização geográfica

### Tabela `ip_statistics`
- IP address
- País
- Total de tentativas
- Tentativas falhadas
- Tentativas bem-sucedidas

## Notas de Segurança

⚠️ **Aviso Legal**: Esta ferramenta foi desenvolvida para fins educacionais e de teste em ambientes autorizados.

- SYN Scan e UDP Flood requerem privilégios `root`
- Apenas use em redes/sistemas que possui permissão
- Verificar legislação local antes de usar

## Requisitos

- Python 3.8+
- root/sudo (para SYN Scan e UDP Flood)
- SSH e/ou Apache/Nginx instalados para logs
- Bibliotecas: scapy, reportlab, matplotlib

## Melhorias Futuras

- Autenticação de utilizadores
- Interface web
- Integração com APIs de GeoIP externas
- Análise de padrões com ML
- Alertas em tempo real
- Mais tipos de logs (Nginx, FTP, etc.)
