# LPD - Trabalho Individual: Network Security Toolkit

Este repositório contém o Trabalho Individual desenvolvido para a disciplina de **LPD**. O projeto consiste num conjunto de ferramentas de rede desenvolvidas em Python, focadas em testes de segurança, análise de tráfego e monitorização de logs.

A aplicação oferece duas interfaces de utilização: uma Interface Gráfica (GUI) e uma Interface de Linha de Comando (CLI).

## 📋 Funcionalidades

O toolkit inclui as seguintes ferramentas e módulos:

### 🛡️ Testes de Rede e Segurança
* **SYN Scan (`SynScan.py`):** Scanner de portas utilizando pacotes SYN para identificar serviços ativos de forma furtiva.
* **Port Knocking (`port_knocking.py`):** Implementação da técnica de segurança para abrir portas através de uma sequência específica de tentativas de conexão.
* **Stress Testing (Simulação):**
    * **SYN Flood (`SynFlood.py`):** Script para teste de stress utilizando pacotes SYN.
    * **UDP Flood (`UdpFlood.py`):** Script para teste de stress utilizando pacotes UDP.

### 📊 Análise e Monitorização
* **Log Analyzer (`log_analyzer_cli.py`):** Ferramenta para analisar logs de sistema e firewall.
    * Suporta análise de `auth.log` (tentativas de login, sudo, etc.).
    * Suporta análise de `ufw.log` (registos da firewall UFW).
* **Persistência de Dados:**
    * Os dados analisados são armazenados em bases de dados SQLite (`log_analysis.db` e `security_logs.db`) para consulta posterior.

## 🚀 Tecnologias Utilizadas

* **Linguagem:** Python 3
* **Interfaces:**
    * GUI: Tkinter / CustomTkinter (via `NetworkToolsGUI.py`)
    * CLI: Command Line Standard (via `main_cli.py`)
* **Base de Dados:** SQLite3

## 📦 Instalação e Requisitos

Certifique-se de que tem o Python instalado. Recomenda-se o uso de um ambiente virtual.

1.  **Clone o repositório:**
    ```bash
    git clone [https://github.com/Tibi-Storage/LPD-TrabalhoIndividual.git](https://github.com/Tibi-Storage/LPD-TrabalhoIndividual.git)
    cd LPD-TrabalhoIndividual
    ```

2.  **Instale as dependências:**
    O projeto possui um ficheiro `requirements.txt`. Instale as bibliotecas necessárias com:
    ```bash
    pip install -r requirements.txt
    ```
    *(Nota: Scripts como o SynScan ou Flood podem necessitar da biblioteca `scapy` ou `socket` raw, o que pode exigir permissões de administrador/root).*

## ⚙️ Como Utilizar

Existem duas formas principais de interagir com o toolkit:

### 1. Interface Gráfica (Recomendado)
Para uma utilização visual das ferramentas:
```bash
python NetworkToolsGUI.py
