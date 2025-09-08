# SquatSpotter


<img width="875" height="225" alt="SquatSpotterLogo" src="https://github.com/user-attachments/assets/a03df59d-1505-4a49-840e-52c30a147f2c" />

A command-line tool to generate, detect, and monitor typosquatting domains. It combines multiple generation techniques, performs fast, multi-threaded DNS checks, and includes an automated surveillance mode with email alerts, ideal for execution via cron jobs.

---

## Features

-   **Advanced Generation**: Creates hundreds of domain variations based on common techniques (omission, repetition, keyboard substitution, homoglyphs, bitsquatting, etc.).
-   **Subdomain Brute-force**: Combines generated variations with a wordlist to expand the detection surface.
-   **Fast DNS Lookups**: Uses **multi-threading** to query thousands of domains in seconds.
-   **Intelligent Categorization**: Classifies domains into clear categories: `complete_info`, `responds_but_empty`, and `no_response`.
-   **CSV Reports**: Generates a detailed `.csv` file containing the analysis results, ready for further use.
-   **Surveillance Mode**: Periodically re-scans an existing list to detect state changes (e.g., an inactive domain becoming active, or a change in MX/NS servers).
-   **Optional Email Alerts**: Sends an email report via SMTP **only if changes are detected** when explicitly enabled in surveillance mode.

---

## Installation

### Prerequisites

-   Python 3.8+
-   `pip` (usually included with Python)

### Steps

1.  **Clone the project (optional) or download the files** into the same directory.
    ```bash
    git clone https://github.com/PaulBerra/SquatSpotter.git
    cd SquatSpotter
    ```

2.  **Install the dependencies**. Using a virtual environment is highly recommended.
    ```bash
    # Create and activate a virtual environment
    python -m venv venv
    source venv/bin/activate  # On Linux/macOS
    # venv\Scripts\activate    # On Windows

    # Install the required libraries
    pip install -r requirements.txt
    ```

3.  **Create and configure the `.env` file** in the project's root directory for email alerts.
    ```env
    # SMTP server configuration for sending alerts
    SMTP_SERVER="smtp.provider.com"
    SMTP_PORT=587
    SMTP_USER="your_address@email.com"
    SMTP_PASSWORD="your_password_or_token"

    # Sender and recipient addresses
    EMAIL_FROM="Typosquatting Alert <your_address@email.com>"
    EMAIL_TO="recipient@email.com"
    ```

---

## Usage

The tool operates in two main modes: an **initial scan** to create a surveillance list, and a **surveillance mode** to monitor that list over time.

### 1. Initial Scan (Creating a Baseline)

This is the first step to generate the domain list and create your baseline file.

-   **Simple and quick scan:**
    ```bash
    python squatspotter.py example.com
    ```

-   **Full scan with results saved to a CSV file:**
    ```bash
    python squatspotter.py example.com -v -o results_example.csv
    ```

-   **Generate the list without performing DNS checks (very fast):**
    ```bash
    python squatspotter.py example.com --no-dns-check -o example.com_list.csv
    ```

### 2. Surveillance Mode (Monitoring for Changes)

This mode is designed to be run automatically. It reads an existing CSV file, re-scans everything, and reports any changes.

-   **Run a silent check (summary only):**
    ```bash
    python squatspotter.py example.com --surveillance example.com_list.csv
    ```

-   **Run a check with detailed output of changes:**
    ```bash
    python squatspotter.py example.com --surveillance example.com_list.csv -v
    ```

-   **Run a check and send an email alert if changes are found:**
    ```bash
    # The domain "example.com" is used for the email subject
    python squatspotter.py example.com --surveillance example.com_list.csv --send-email
    ```
### 3. Manual 

```
usage: SquatSpotter.py [-h] [-w WORDLIST] [-o OUTPUT] [-v] [--no-bruteforce] [--no-dns-check] [--surveillance SURVEILLANCE] [--send-email] [domaine]

Outil de génération et de vérification de typosquatting.

positional arguments:
  domaine               Le domaine cible pour un NOUVEAU scan.

options:
  -h, --help            show this help message and exit
  -w WORDLIST, --wordlist WORDLIST
                        Wordlist de sous-domaines.
                        (défaut: french.dict)
  -o OUTPUT, --output OUTPUT
                        Fichier de sortie CSV pour les résultats.
  -v, --verbose         Affiche des informations détaillées.
  --no-bruteforce       Désactive le bruteforce de sous-domaines.
  --no-dns-check        Désactive la vérification DNS.
  --surveillance SURVEILLANCE
                        Lance le mode surveillance sur un fichier CSV existant.
  --send-email          Active l'envoi d'email en mode surveillance.

```




---

## Automation with Cron

To automate the monitoring, you can add the script to your crontab.

1.  Open the cron editor:
    ```bash
    crontab -e
    ```

2.  Add a line to schedule the execution.

    -   **Example for a silent daily check at 2:00 AM:**
        ```crontab
        # Run typosquatting surveillance for example.com every day at 2 AM
        0 2 * * * /usr/bin/python3 /path/to/squatspotter.py example.com --surveillance /path/to/example.com_list.csv
        ```

    -   **Example for a daily check with email alerts:**
        ```crontab
        # Run surveillance and send email alerts on changes
        0 2 * * * /usr/bin/python3 /path/to/squatspotter.py example.com --surveillance /path/to/example.com_list.csv --send-email
        ```

---

## Command-line Arguments

| Argument | Short | Description |
| :--- | :--- | :--- |
| `domaine` | | **Required** for a new scan, or for the email subject in surveillance mode. |
| `--surveillance <file>`| | **Activates surveillance mode** on an existing CSV file. |
| `--output <file>` | `-o` | Output CSV file to save detailed results for a **new scan**. |
| `--wordlist <file>` | `-w` | Path to the subdomain wordlist for brute-forcing. |
| `--verbose` | `-v` | Displays detailed information, including inactive domains in a new scan, or change details in surveillance mode. |
| `--send-email` | | **Enables email alerts** in surveillance mode if changes are detected. Requires a configured `.env` file. |
| `--no-bruteforce` | | Disables the subdomain brute-force step in a new scan. |
| `--no-dns-check` | | Disables DNS verification in a new scan and only generates the potential domain list. |
| `--help` | `-h` | Shows the help message and exits. |
