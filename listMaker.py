import tldextract
import string
import os # Ajout du module os pour gérer les fichiers de l'exemple

# --- Dictionnaires et listes de configuration (massivement étendus) ---

# Voisins de clavier pour QWERTY et AZERTY combinés
VOISINS_CLAVIER = {
    'q': 'azsw', 'w': 'qasde', 'e': 'wsdfr', 'r': 'edfgt', 't': 'rfghy', 'y': 'tghju',
    'u': 'yhjki', 'i': 'ujklo', 'o': 'iklp', 'p': 'ol',
    'a': 'qwsz', 's': 'qwedcxz', 'd': 'werfvcxs', 'f': 'ertgbvcd', 'g': 'rtyhnbvf',
    'h': 'tyujmnbg', 'j': 'yuikmnb', 'k': 'uionmjl', 'l': 'iopkm',
    'z': 'asdx', 'x': 'sdcz', 'c': 'dfvx', 'v': 'fgbc', 'b': 'ghnv', 'n': 'hjmb',
    'm': 'jknl',
    '1': '2q', '2': '1qwa', '3': '2wse', '4': '3edr', '5': '4rft', '6': '5tgy',
    '7': '6yhu', '8': '7uji', '9': '8iko', '0': '9olp'
}

# Caractères visuellement similaires (homoglyphes)
HOMOGLYPHES = {
    'o': ['0'], 'l': ['1', 'i', 'I'], 'i': ['1', 'l'], 'g': ['q', '9'], 'e': ['3'],
    'a': ['@'], 'b': ['6', '8'], 's': ['5', '$'], 'vv': ['w'], 'rn': ['m'],
    'cl': ['d'], 'nn': ['m']
}

# TLDs couramment utilisés pour le typosquatting
TLDS_COMMUNS = [
    'co', 'net', 'org', 'info', 'biz', 'xyz', 'club', 'site', 'online', 'shop',
    'top', 'eu', 'fr', 'io', 'ai', 'ly', 'cm', 'cn', 'ws', 'cc', 'gq', 'ml',
    'cf', 'ga', 'tk', 'ru', 'su'
]

# Préfixes et suffixes souvent utilisés dans les attaques de phishing
AFFIXES = [
    'support', 'login', 'secure', 'account', 'verify', 'portal', 'app', 'my',
    'help', 'service', 'admin', 'user'
]


# --- Fonctions de génération de variations de typosquatting ---

def _omission(mot):
    """Supprime un caractère (go_ogle -> gogle)."""
    return {mot[:i] + mot[i+1:] for i in range(len(mot))}

def _repetition(mot):
    """Répète un caractère (google -> googgle)."""
    return {mot[:i] + c + mot[i:] for i, c in enumerate(mot)}

def _transposition(mot):
    """Inverse deux caractères adjacents (google -> goolge)."""
    return {mot[:i] + mot[i+1] + mot[i] + mot[i+2:] for i in range(len(mot)-1)}

def _substitution_clavier(mot):
    """Remplace un caractère par un voisin du clavier."""
    variations = set()
    for i, c in enumerate(mot):
        if c in VOISINS_CLAVIER:
            for v in VOISINS_CLAVIER[c]:
                variations.add(mot[:i] + v + mot[i+1:])
    return variations

def _homoglyphes(mot):
    """Remplace des caractères/groupes par des caractères visuellement similaires."""
    variations = set()
    # Remplacement de caractères uniques
    for i, c in enumerate(mot):
        if c in HOMOGLYPHES:
            for g in HOMOGLYPHES[c]:
                variations.add(mot[:i] + g + mot[i+1:])
    # Remplacement de groupes (ex: 'rn' -> 'm')
    for group, replacements in HOMOGLYPHES.items():
        if len(group) > 1 and group in mot:
            for rep in replacements:
                variations.add(mot.replace(group, rep))
    return variations

def _split_domaine(mot):
    """Ajoute un point dans le domaine (google -> go.ogle)."""
    return {mot[:i] + '.' + mot[i:] for i in range(1, len(mot))}

def _ajout_tiret(mot):
    """Ajoute un tiret dans le domaine (google -> g-oogle)."""
    return {mot[:i] + '-' + mot[i:] for i in range(1, len(mot))}

def _bitsquatting(mot):
    """Simule une inversion de bit dans un caractère (google -> goigle, googme)."""
    variations = set()
    # Caractères autorisés dans les noms de domaine (simplifié)
    caracteres_valides = string.ascii_letters + string.digits + '-'
    masques = [1, 2, 4, 8, 16, 32, 64, 128]
    for i, c in enumerate(mot):
        for masque in masques:
            b = chr(ord(c) ^ masque)
            # MODIFICATION : Remplacement de .isalnum() par un filtre plus strict
            if b in caracteres_valides:
                variations.add(mot[:i] + b + mot[i+1:])
    return variations

def _double_frappe(mot):
    """Simule une double frappe avec une touche adjacente (google -> goovle)."""
    variations = set()
    for i, c in enumerate(mot):
        if c in VOISINS_CLAVIER:
            for v in VOISINS_CLAVIER[c]:
                variations.add(mot[:i] + c + v + mot[i+1:])
    return variations

def _echange_voyelles(mot):
    """Échange les voyelles (google -> gaagle, geegle, ...)."""
    variations = set()
    voyelles = "aeiou"
    for i, c in enumerate(mot):
        if c in voyelles:
            for v in voyelles:
                if v != c:
                    variations.add(mot[:i] + v + mot[i+1:])
    return variations


# --- Générateur principal de typosquatting ---

def generer_typosquatting(domaine_complet):
    """Génère une liste complète de domaines potentiels basés sur des techniques étendues."""
    try:
        extraction = tldextract.extract(domaine_complet)
    except Exception:
        return [f"Erreur: Impossible d'analyser le domaine '{domaine_complet}'."]
    
    sous_domaine = extraction.subdomain
    domaine = extraction.domain
    tld = extraction.suffix

    if not domaine:
        return [f"Erreur: Domaine principal non détecté dans '{domaine_complet}'."]

    variations = set()
    techniques_mot = [
        _omission, _repetition, _transposition, _substitution_clavier,
        _homoglyphes, _split_domaine, _ajout_tiret, _bitsquatting,
        _double_frappe, _echange_voyelles
    ]
    # Appliquer les techniques au DOMAINE PRINCIPAL
    for func in techniques_mot:
        for var in func(domaine):
            variations.add(f"{sous_domaine}.{var}.{tld}" if sous_domaine else f"{var}.{tld}")
    # Appliquer les techniques au SOUS-DOMAINE
    if sous_domaine:
        for func in techniques_mot:
            for var in func(sous_domaine):
                variations.add(f"{var}.{domaine}.{tld}")
    # Générer les variations de TLD
    domaine_base = f"{sous_domaine}.{domaine}" if sous_domaine else domaine
    for faux_tld in TLDS_COMMUNS:
        if faux_tld != tld:
            variations.add(f"{domaine_base}.{faux_tld}")
    # Générer les variations structurelles
    for affix in AFFIXES:
        variations.add(f"{affix}-{domaine_base}.{tld}")
        variations.add(f"{domaine_base}-{affix}.{tld}")
    if sous_domaine:
        variations.add(f"{sous_domaine}{domaine}.{tld}")
        variations.add(f"{domaine}-{sous_domaine}.{tld}")
    variations.add(domaine_complet)
    return sorted(list(variations))


# --- NOUVELLE FONCTION ---

def generer_bruteforce_sous_domaines(chemin_fichier_domaines, chemin_fichier_sous_domaines):
    """
    Combine une liste de domaines avec une wordlist de sous-domaines.
    
    :param chemin_fichier_domaines: Fichier texte avec un domaine par ligne (ex: google.com)
    :param chemin_fichier_sous_domaines: Fichier texte avec un sous-domaine par ligne (ex: www, mail)
    :return: Une liste de tous les domaines combinés (ex: www.google.com, mail.google.com)
    """
    print(f"\nCombinaison des domaines de '{chemin_fichier_domaines}' avec les sous-domaines de '{chemin_fichier_sous_domaines}'...")
    
    domaines_combines = set()
    
    try:
        # MODIFICATION : Ajout de encoding='utf-8'
        with open(chemin_fichier_domaines, 'r', encoding='utf-8') as f_domaines:
            domaines_base = [line.strip() for line in f_domaines if line.strip()]
            
        # MODIFICATION : Ajout de encoding='utf-8'
        with open(chemin_fichier_sous_domaines, 'r', encoding='utf-8') as f_sous_domaines:
            sous_domaines = [line.strip() for line in f_sous_domaines if line.strip()]

    except FileNotFoundError as e:
        return [f"Erreur: Le fichier '{e.filename}' est introuvable."]
    except UnicodeDecodeError:
        return [f"Erreur d'encodage: Le fichier '{chemin_fichier_domaines}' ou '{chemin_fichier_sous_domaines}' n'est pas en UTF-8."]
    
    for domaine in domaines_base:
        for sous_domaine in sous_domaines:
            domaines_combines.add(f"{sous_domaine}.{domaine}")
            
    print(f"Bruteforce terminé. {len(domaines_combines)} domaines uniques générés.")
    return sorted(list(domaines_combines))


