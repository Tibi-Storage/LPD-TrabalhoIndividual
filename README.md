# Network Tools Suite - LPD 🛡️

Este repositório contém o trabalho individual desenvolvido para a unidade curricular de **Linguagens de Programação Dinâmicas (LPD)** no Mestrado de Segurança Informática. Trata-se de um toolkit modular de rede, integrando ferramentas de auditoria, testes de carga e análise forense.

## 🚀 Funcionalidades Principais

O projeto está dividido em quatro módulos core:

1.  **SYN Scan (`SynScan.py`):** Realiza varrimentos de portas utilizando a técnica *Stealth Scan* (Half-open), enviando pacotes SYN e fechando a conexão com RST para evitar logs excessivos no alvo.
2.  **Stress Testing (DoS Simulation):**
    * `SynFlood.py`: Inunda o alvo com pacotes SYN e IPs falsificados (*spoofing*).
    * `UdpFlood.py`: Envia pacotes UDP de alta frequência com payloads aleatórios.
3.  **Port Knocking (`port_knocking.py`):** Cliente para validação de sequências de "batidas" em portas fechadas para gestão de acesso dinâmico (ex: abrir porta SSH).
4.  **Log Analyzer (`log_analyzer_cli.py`):** Motor de análise que processa logs do sistema (`auth.log`) e da firewall (`ufw.log`), identificando ataques e armazenando estatísticas em base de dados SQLite.

## 🖥️ Interfaces de Utilização

O toolkit oferece flexibilidade total através de duas interfaces:

* **Interface Gráfica (GUI):** Executada via `NetworkToolsGUI.py`, oferece uma experiência visual com suporte a multi-threading para não bloquear a interface durante os scans. Permite a exportação de relatórios em PDF.
* **Linha de Comando (CLI):** Executada via `main_cli.py`, ideal para automação e utilização em servidores via SSH.

## 🛠️ Tecnologias e Bibliotecas

* **Linguagem:** Python 3.x
* **Manipulação de Pacotes:** [Scapy](https://scapy.net/)
* **Interface Visual:** Tkinter / ttk
* **Base de Dados:** SQLite3
* **Relatórios:** ReportLab (para exportação em PDF)

## 📦 Instalação e Execução

### Pré-requisitos
Devido à utilização do Scapy para manipulação de pacotes raw, este projeto deve ser executado em ambiente **Linux** com privilégios de **root**.

```bash
# Instalar dependências
sudo pip install -r requirements.txt
Como executar
Para iniciar a Interface Gráfica:

Bash
sudo python NetworkToolsGUI.py
Para utilizar a CLI:

Bash
# Exemplo de scan de portas
sudo python main_cli.py scan 192.168.1.1 -p 22,80,443

# Exemplo de análise de logs
sudo python main_cli.py logs --ssh auth.log --ufw ufw.log

NetworkToolsGUI.py: Ponto de entrada da aplicação gráfica.

main_cli.py: Ponto de entrada da aplicação via terminal.


auth.log / ufw.log: Ficheiros de exemplo para teste do analisador.

⚠️ Aviso Legal (Disclaimer)
Este projeto foi desenvolvido estritamente para fins académicos e pedagógicos. O autor não se responsabiliza pelo uso indevido destas ferramentas. Realizar ataques de negação de serviço ou varrimentos sem autorização em redes alheias é ilegal.