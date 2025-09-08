import dns.resolver

def get_dns_info(domain):
    """
    Vérifie si un domaine a une réponse DNS, et si oui, extrait les enregistrements NS and MX.

    Args:
        domain (str): Le nom de domaine à vérifier.

    Returns:
        dict: Un dictionnaire contenant les enregistrements 'ns' et 'mx',
              ou un dictionnaire avec une clé 'error' si le domaine n'existe pas.
    """
    dns_records = {}

    # --- Vérification de l'existence du domaine (requête pour les enregistrements NS) ---
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        dns_records['ns'] = sorted([str(ns.target) for ns in ns_records])
    except dns.resolver.NXDOMAIN:
        return {'error': f"Le domaine '{domain}' n'existe pas."}
    except dns.resolver.NoAnswer:
        dns_records['ns'] = []
    except dns.exception.Timeout:
        return {'error': f"Timeout lors de la résolution de '{domain}'."}
    except Exception as e:
        return {'error': f"Une erreur inattendue est survenue : {e}"}

    # --- Extraction des enregistrements MX ---
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_list = []
        for mx in mx_records:
            mx_list.append({
                'priority': mx.preference,
                'exchange': str(mx.exchange)
            })
        # Trie les serveurs de messagerie par priorité
        dns_records['mx'] = sorted(mx_list, key=lambda x: x['priority'])
    except dns.resolver.NoAnswer:
        dns_records['mx'] = []
    except Exception:
        # Si une erreur se produit ici, nous avons déjà les enregistrements NS
        dns_records['mx'] = []

    return dns_records

