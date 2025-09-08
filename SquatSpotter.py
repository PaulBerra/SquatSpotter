import argparse
import sys
import csv
import os
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
from tqdm import tqdm
from colorama import Fore, Style, init
import dotenv
import concurrent.futures

# --- Dépendances externes (assurez-vous que ces fichiers sont présents) ---
try:
    from dnschecker import get_dns_info
    from listMaker import generer_typosquatting, generer_bruteforce_sous_domaines
except ImportError as e:
    print(f"{Fore.RED}Erreur: Le module '{e.name}' est introuvable.{Style.RESET_ALL}")
    print("Assurez-vous que les fichiers 'dnschecker.py' et 'listMaker.py' sont bien présents.")
    sys.exit(1)

# --- Initialisation des modules ---
init(autoreset=True)
dotenv.load_dotenv()

# --- Fonctions Utilitaires ---

def verifier_domaine(domain):
    """Vérifie un seul domaine et retourne son dictionnaire de résultat."""
    info = get_dns_info(domain)
    resultat = {"domaine": domain, "ns": "", "mx": "", "registered": False, "categorie": ""}

    if 'error' not in info:
        resultat["registered"] = True
        ns_records = "; ".join(info.get('ns', []))
        mx_data = info.get('mx', [])
        mx_records_list = [f"{rec.get('exchange', '')} (prio {rec.get('priority', 'N/A')})" for rec in mx_data]
        mx_records = "; ".join(mx_records_list)
        resultat["ns"] = ns_records
        resultat["mx"] = mx_records
        resultat["categorie"] = "repond_infos_completes" if (ns_records or mx_records) else "repond_mais_vide"
    else:
        resultat["categorie"] = "ne_repond_pas"
        resultat["error_message"] = info['error']

    return resultat

def envoyer_email_alerte(changements, domaine_cible):
    """Envoie un email si des changements sont détectés."""
    smtp_server, smtp_port, smtp_user, smtp_password, email_from, email_to = (
        os.getenv("SMTP_SERVER"), os.getenv("SMTP_PORT"), os.getenv("SMTP_USER"),
        os.getenv("SMTP_PASSWORD"), os.getenv("EMAIL_FROM"), os.getenv("EMAIL_TO")
    )

    if not all([smtp_server, smtp_port, smtp_user, smtp_password, email_from, email_to]):
        print(f"{Fore.RED}Erreur: Variables d'environnement pour l'email manquantes dans le fichier .env.{Style.RESET_ALL}")
        return

    print(f"Préparation de l'alerte email pour {email_to}...")
    date_scan = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sujet = f"Alerte Typosquatting pour {domaine_cible} - {date_scan}"
    corps_html = f"""
    <html><body>
        <h2>Rapport de surveillance Typosquatting pour {domaine_cible}</h2>
        <p><strong>Date du scan :</strong> {date_scan}</p>
        <p>Les changements suivants ont été détectés :</p>
        <ul>{''.join([f'<li>{c}</li>' for c in changements])}</ul>
    </body></html>
    """
    msg = MIMEText(corps_html, 'html')
    msg['Subject'] = sujet
    msg['From'] = email_from
    msg['To'] = email_to

    try:
        with smtplib.SMTP(smtp_server, int(smtp_port)) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(email_from, email_to, msg.as_string())
        print(f"{Fore.GREEN}Email d'alerte envoyé avec succès.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Échec de l'envoi de l'email : {e}{Style.RESET_ALL}")

def strip_html(text):
    """Nettoie les balises HTML simples pour l'affichage console."""
    return text.replace('<strong>', '').replace('</strong>', '').replace('<em>', '').replace('</em>', '')

def lancer_surveillance(fichier_csv, domaine_cible, verbose=False, send_email=False):
    """Lit un fichier CSV, re-scanne les domaines et détecte les changements."""
    print(f"{Fore.CYAN}--- Lancement du mode surveillance sur '{fichier_csv}' ---{Style.RESET_ALL}")
    
    if not os.path.exists(fichier_csv):
        print(f"{Fore.RED}Erreur: Le fichier '{fichier_csv}' est introuvable. Lancez un scan initial pour le créer.{Style.RESET_ALL}")
        return

    try:
        with open(fichier_csv, 'r', newline='', encoding='utf-8') as f:
            etat_precedent = {row['domaine']: row for row in csv.DictReader(f)}
    except Exception as e:
        print(f"{Fore.RED}Erreur lors de la lecture du fichier CSV : {e}{Style.RESET_ALL}")
        return

    domaines_a_scanner = list(etat_precedent.keys())
    print(f"{len(domaines_a_scanner)} domaines à re-scanner...")

    changements, resultats_actualises = [], []

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        resultats_map = executor.map(verifier_domaine, domaines_a_scanner)
        
        for etat_actuel in tqdm(resultats_map, total=len(domaines_a_scanner), desc="Surveillance", unit="domaine"):
            
            # --- BLOC CORRIGÉ ---
            # 1. On récupère d'abord le nom du domaine depuis le résultat actuel.
            domain = etat_actuel["domaine"]
            # 2. Ensuite, on utilise ce nom pour chercher l'état précédent.
            ancien_etat = etat_precedent.get(domain, {})
            # --- FIN DU BLOC CORRIGÉ ---

            if ancien_etat.get('categorie') != etat_actuel['categorie']:
                msg = f"<strong>{domain}</strong> est passé de <em>{ancien_etat.get('categorie', 'inconnu')}</em> à <em>{etat_actuel['categorie']}</em>"
                changements.append(msg)
            elif ancien_etat.get('ns') != etat_actuel['ns']:
                msg = f"Les serveurs NS de <strong>{domain}</strong> ont changé."
                changements.append(msg)
            elif ancien_etat.get('mx') != etat_actuel['mx']:
                msg = f"Les serveurs MX de <strong>{domain}</strong> ont changé."
                changements.append(msg)
            
            resultats_actualises.append(etat_actuel)

    print(f"\nMise à jour du fichier de surveillance '{fichier_csv}'...")
    try:
        with open(fichier_csv, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ["domaine", "ns", "mx", "registered", "categorie", "error_message"]
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(resultats_actualises)
        print(f"{Fore.GREEN}Fichier mis à jour.{Style.RESET_ALL}")
    except IOError as e:
        print(f"{Fore.RED}Erreur lors de la mise à jour du fichier : {e}{Style.RESET_ALL}")

    print("\n--- Résumé de la surveillance ---")
    if changements:
        print(f"{Fore.YELLOW}{len(changements)} changement(s) détecté(s).{Style.RESET_ALL}")
        if verbose:
            print("Détails des changements :")
            for ch in changements:
                print(f"- {strip_html(ch)}")
    else:
        print(f"{Fore.GREEN}Aucun changement détecté.{Style.RESET_ALL}")
    
    if send_email and changements:
        envoyer_email_alerte(changements, domaine_cible)

def main():
    """Fonction principale du script."""
    parser = argparse.ArgumentParser(
        description="Outil de génération et de vérification de typosquatting.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("domaine", nargs='?', default=None, help="Le domaine cible pour un NOUVEAU scan.")
    parser.add_argument("-w", "--wordlist", default="dict/french.dict", help="Wordlist de sous-domaines.\n(défaut: french.dict)")
    parser.add_argument("-o", "--output", help="Fichier de sortie CSV pour les résultats.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Affiche des informations détaillées.")
    parser.add_argument("--no-bruteforce", action="store_true", help="Désactive le bruteforce de sous-domaines.")
    parser.add_argument("--no-dns-check", action="store_true", help="Désactive la vérification DNS.")
    parser.add_argument("--surveillance", help="Lance le mode surveillance sur un fichier CSV existant.")
    parser.add_argument("--send-email", action="store_true", help="Active l'envoi d'email en mode surveillance.")

    args = parser.parse_args()

    if args.surveillance:
        if not args.domaine:
            print(f"{Fore.RED}Erreur: Le mode --surveillance requiert le nom du domaine cible pour les alertes.{Style.RESET_ALL}")
            sys.exit(1)
        lancer_surveillance(args.surveillance, args.domaine, args.verbose, args.send_email)
        sys.exit(0)

    if not args.domaine:
        parser.print_help()
        sys.exit(1)

    # --- Mode de Scan Initial ---
    print(f"{Fore.CYAN}--- Étape 1: Génération des variations de typosquatting pour '{args.domaine}' ---{Style.RESET_ALL}")
    liste_typos = generer_typosquatting(args.domaine)
    print(f"{Fore.GREEN}▶ {len(liste_typos)} variations de base générées.{Style.RESET_ALL}")

    domaines_a_tester = set(liste_typos)
    temp_domaine_file = "typos_temp.txt"

    if not args.no_bruteforce:
        print(f"\n{Fore.CYAN}--- Étape 2: Bruteforce des sous-domaines avec '{args.wordlist}' ---{Style.RESET_ALL}")
        with open(temp_domaine_file, "w", encoding='utf-8') as f:
            for typo in liste_typos:
                f.write(typo + "\n")
        
        liste_bruteforce = generer_bruteforce_sous_domaines(temp_domaine_file, args.wordlist)
        
        if liste_bruteforce and not liste_bruteforce[0].startswith("Erreur:"):
            print(f"{Fore.GREEN}▶ {len(liste_bruteforce)} domaines supplémentaires générés.{Style.RESET_ALL}")
            domaines_a_tester.update(liste_bruteforce)
        else:
            print(f"{Fore.YELLOW}Avertissement: Le bruteforce n'a rien donné ou a rencontré une erreur.{Style.RESET_ALL}")
            if liste_bruteforce: print(f"{Fore.RED}{liste_bruteforce[0]}{Style.RESET_ALL}")
    
    if os.path.exists(temp_domaine_file):
        os.remove(temp_domaine_file)

    domaines_a_verifier = sorted(list(domaines_a_tester))
    print(f"\n{Fore.YELLOW}Total de {len(domaines_a_verifier)} domaines uniques générés.{Style.RESET_ALL}")
    
    resultats_analyses = []

    if args.no_dns_check:
        print(f"\n{Fore.CYAN}--- Étape 3: Vérification DNS désactivée ---{Style.RESET_ALL}")
        print("Création de la liste de résultats sans analyse.")
        for domain in domaines_a_verifier:
            resultats_analyses.append({
                "domaine": domain, "ns": "", "mx": "", "registered": False, "categorie": "non_verifie"
            })
    else:
        print(f"\n{Fore.CYAN}--- Étape 3: Vérification DNS (mode multi-thread) ---{Style.RESET_ALL}")
        
        resultats_bruts = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            resultats_map = executor.map(verifier_domaine, domaines_a_verifier)
            
            for resultat in tqdm(resultats_map, total=len(domaines_a_verifier), desc="Vérification DNS", unit="domaine"):
                resultats_bruts.append(resultat)
        
        for resultat in resultats_bruts:
            categorie, domain = resultat["categorie"], resultat["domaine"]

            if categorie == "repond_infos_completes":
                print(f"{Fore.GREEN}[+] Domaine avec infos DNS : {domain}{Style.RESET_ALL}")
                resultats_analyses.append(resultat)
            elif categorie == "repond_mais_vide":
                print(f"{Fore.YELLOW}[-] Domaine répond mais sans NS/MX : {domain}{Style.RESET_ALL}")
                resultats_analyses.append(resultat)
            elif categorie == "ne_repond_pas" and args.verbose:
                print(f"{Fore.RED}[x] Domaine inactif : {domain} ({resultat.get('error_message', 'N/A')}){Style.RESET_ALL}")
                resultats_analyses.append(resultat)

    # --- FIN DU SCRIPT ET GÉNÉRATION DU RAPPORT ---
    print(f"\n{Fore.GREEN}Traitement terminé !{Style.RESET_ALL}")

    cat_complet = len([r for r in resultats_analyses if r['categorie'] == 'repond_infos_completes'])
    cat_vide = len([r for r in resultats_analyses if r['categorie'] == 'repond_mais_vide'])
    cat_inactif = len([r for r in resultats_analyses if r['categorie'] == 'ne_repond_pas'])
    cat_non_verifie = len([r for r in resultats_analyses if r['categorie'] == 'non_verifie'])

    if not args.no_dns_check:
        print("\n--- Résumé de l'analyse ---")
        print(f"{Fore.GREEN}Domaines avec infos complètes : {cat_complet}")
        print(f"{Fore.YELLOW}Domaines qui répondent (sans NS/MX) : {cat_vide}")
        if args.verbose:
            print(f"{Fore.RED}Domaines inactifs (inclus dans le rapport) : {cat_inactif}")
    else:
        print(f"\nTotal des domaines listés : {cat_non_verifie}")

    if args.output:
        print(f"\nSauvegarde des résultats dans le fichier CSV '{args.output}'...")
        try:
            with open(args.output, "w", newline="", encoding='utf-8') as f:
                fieldnames = ["domaine", "ns", "mx", "registered", "categorie", "error_message"]
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(resultats_analyses)
            print(f"{Fore.GREEN}Sauvegarde terminée avec succès.{Style.RESET_ALL}")
        except IOError as e:
            print(f"{Fore.RED}Erreur lors de l'écriture du fichier : {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()