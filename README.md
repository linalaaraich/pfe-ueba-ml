# Système UEBA Portable — Détection Insider Threat & Malware

**Projet de Fin d'Études (PFE)**  
**Cires Technologies — Tanger Med Group**  
**Auteure : Assia**

---

## Description

Ce projet implémente un système **UEBA (User and Entity Behavior Analytics)** portable basé sur le Machine Learning non supervisé, intégré à Wazuh SIEM. L'objectif est de détecter en temps réel les menaces internes (Insider Threats) et les malwares dans un contexte SOC.

### Architecture de détection

```
VM2 (Windows Server 2022)          VM1 (Ubuntu 24.04)
┌─────────────────────────┐        ┌────────────────────────────────────┐
│  Active Directory        │        │  Wazuh Manager + Dashboard         │
│  Wazuh Agent            │──────►│  alerts.json                       │
│  Sysmon                 │        │         │                          │
│  user_normal (9h-18h)   │        │         ▼                          │
└─────────────────────────┘        │  parse_logs.py → Features UEBA     │
                                   │         │                          │
                                   │         ▼                          │
                                   │  Ensemble ML (vote majoritaire)    │
                                   │  ┌──────────────────────────────┐  │
                                   │  │ Isolation Forest (IF)        │  │
                                   │  │ One-Class SVM (OCSVM)        │  │
                                   │  │ Autoencoder (AE)             │  │
                                   │  └──────────────────────────────┘  │
                                   │         │                          │
                                   │         ▼                          │
                                   │  /var/log/ueba_alerts.json         │
                                   └────────────────────────────────────┘
```

### Modèles ML (100% Non Supervisé)

| Modèle | Type | Cible principale |
|--------|------|-----------------|
| Isolation Forest | Arbre d'isolation | Anomalies comportementales (Insider Threat + Malware) |
| One-Class SVM | SVM à frontière | Compromission de compte |
| Autoencoder | Deep Learning | Anomalies subtiles (encodage/décodage) |

Vote majoritaire : **alerte levée si ≥ 2 modèles sur 3 détectent une anomalie**.

---

## Structure du projet

```
pfe-ueba/
├── ueba_ml_pipeline.ipynb    # Notebook Jupyter — pipeline ML complet
├── parse_logs.py             # Extraction features depuis alerts.json
├── wazuh_integration.py      # Daemon temps réel Wazuh
├── requirements.txt          # Dépendances Python
├── README.md                 # Ce fichier
└── models/                   # Créé automatiquement par le notebook
    ├── isolation_forest.pkl
    ├── one_class_svm.pkl
    ├── autoencoder.pkl
    ├── autoencoder.keras
    ├── scaler.pkl
    └── ae_threshold.json
```

---

## Installation

### Prérequis
- Python 3.10+
- (optionnel) Google Colab pour le notebook

### Environnement local

```bash
git clone https://github.com/<votre-compte>/pfe-ueba.git
cd pfe-ueba

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

### Google Colab

Ouvrir `ueba_ml_pipeline.ipynb` directement dans Google Colab — la première cellule installe toutes les dépendances automatiquement.

---

## Utilisation

### 1. Entraînement des modèles (Notebook)

Ouvrir `ueba_ml_pipeline.ipynb` et exécuter toutes les cellules dans l'ordre. Le notebook :
1. Charge `alerts.json` (ou génère des données simulées si absent)
2. Extrait les features UEBA via `parse_logs.py`
3. Entraîne les 3 modèles sur le comportement normal
4. Exporte les modèles dans `./models/`
5. Valide sur des scénarios d'attaque simulés

### 2. Extraction manuelle des features

```bash
# Extraire les features depuis alerts.json et exporter en CSV
python3 parse_logs.py /var/ossec/logs/alerts/alerts.json \
    --output ueba_features.csv \
    --session-min 60
```

### 3. Daemon temps réel (VM1)

```bash
# Démarrer la surveillance en temps réel
python3 wazuh_integration.py \
    --alerts /var/ossec/logs/alerts/alerts.json \
    --models ./models/ \
    --poll 30 \
    --verbose
```

Les alertes sont écrites dans :
- **Console** : log coloré avec niveau de sévérité
- **Fichier** : `/var/log/ueba_alerts.json` (format NDJSON)

### 4. Lancement en service systemd (production)

Créer `/etc/systemd/system/ueba.service` :

```ini
[Unit]
Description=UEBA Detection Daemon
After=network.target

[Service]
Type=simple
User=wazuh
WorkingDirectory=/opt/ueba
ExecStart=/opt/ueba/venv/bin/python3 /opt/ueba/wazuh_integration.py \
    --alerts /var/ossec/logs/alerts/alerts.json \
    --models /opt/ueba/models/
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable ueba
systemctl start ueba
systemctl status ueba
```

---

## Features UEBA extraites

| Feature | Description | Type |
|---------|-------------|------|
| `hour` | Heure de la session (0-23) | Numérique |
| `is_night` | 1 si heure < 9h ou > 18h | Binaire |
| `is_weekend` | 1 si samedi ou dimanche | Binaire |
| `nb_files_accessed` | Nombre de fichiers accédés | Numérique |
| `nb_sensitive_files` | Accès au dossier C:\Sensitive\ | Numérique |
| `nb_failed_logins` | Nombre de tentatives échouées (4625) | Numérique |
| `nb_processes` | Nombre de processus créés | Numérique |
| `bytes_sent` | Volume réseau émis | Numérique |
| `new_ip` | 1 si nouvelle IP détectée | Binaire |
| `sensitive_path_access` | 1 si C:\Sensitive\ accédé | Binaire |
| `process_name` | Nom du premier processus lancé | Textuel |
| `command_line` | Ligne de commande | Textuel |
| `z_score_files` | Z-score des fichiers accédés | Numérique |
| `z_score_logins` | Z-score des logins échoués | Numérique |
| `velocity` | Fichiers accédés par minute | Numérique |
| `entropy_commands` | Entropie de Shannon des commandes | Numérique |

---

## Sources de logs Wazuh

| Event ID | Source | Signification |
|----------|--------|---------------|
| 4624 | Windows Security | Connexion réussie |
| 4625 | Windows Security | Connexion échouée |
| 4634 | Windows Security | Déconnexion |
| 4688 | Windows Security | Processus créé |
| 4663 | Windows Security | Objet accédé |
| 1 | Sysmon | Création de processus |
| 3 | Sysmon | Connexion réseau |
| 11 | Sysmon | Fichier créé |
| 13 | Sysmon | Modification registre |
| 22 | Sysmon | Requête DNS |

---

## Scénarios de test

### Insider Threat simulé
- Connexion hors heures (nuit/week-end)
- Accès massif à C:\Sensitive\
- Exfiltration de données (volume réseau élevé)

### Malware simulé
- Exécution de processus inhabituels (`powershell.exe -enc ...`)
- Connexions réseau anormales (nouvelles IPs)
- Modifications du registre Windows
- Requêtes DNS suspectes

---

## Portabilité

Le système est conçu pour être **SIEM-agnostique** :
- Les features reposent sur des **déviations comportementales** (z-scores, entropie)
- Le parseur `parse_logs.py` peut être adapté à tout format de log structuré
- Les modèles `.pkl` fonctionnent indépendamment de Wazuh

---

## Technologies utilisées

- **SIEM** : Wazuh 4.x
- **OS** : Ubuntu 24.04 LTS / Windows Server 2022
- **Cloud** : Microsoft Azure (2 VMs)
- **ML** : scikit-learn, TensorFlow/Keras
- **Langage** : Python 3.10+

---

## Licence

Projet académique — PFE 2024  
Cires Technologies / Tanger Med Group
