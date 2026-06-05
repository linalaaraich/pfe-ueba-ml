# Données réelles (OTRF) + démo locale gratuite — guide pas à pas

Ce guide résout l'impasse « pas de vraies données / cloud 24/7 trop cher » :
1. **Données** : entraîner/évaluer sur de la VRAIE télémétrie Windows/Sysmon via
   les jeux **OTRF Security-Datasets** (gratuit, hors-ligne).
2. **Démo live** : montrer la chaîne Wazuh → daemon → alerte sur une **VM locale
   gratuite** (aucun coût cloud).

---

## Partie 1 — Données réelles via OTRF Security-Datasets

> Pas besoin de machine 24/7 : on rejoue des captures réelles d'événements
> Windows/Sysmon, au format que votre pipeline comprend désormais.

### 1.1 Récupérer un dataset
Dépôt : <https://github.com/OTRF/Security-Datasets> (dossiers
`datasets/atomic/windows/…` pour des techniques unitaires, `datasets/compound/…`
pour des scénarios APT complets). Choisissez des captures **Sysmon / Security**.

```bash
git clone --depth 1 https://github.com/OTRF/Security-Datasets.git
# exemples utiles :
#  - atomic/windows/defense_evasion/...  (process/Sysmon EID 1, command lines)
#  - atomic/windows/credential_access/... (logons 4624/4625)
#  - compound/...                          (scénarios multi-étapes = "attaque")
# Les fichiers sont des .json (souvent NDJSON), parfois .zip/.gz à décompresser.
```

### 1.2 Convertir en dataset.csv (adaptateur fourni)
```bash
cd pfe-ueba-ml
pip install -e .
python -m ueba.features.otrf /chemin/vers/dataset.json --output data/dataset.csv
```
L'adaptateur (`src/ueba/features/otrf.py`) mappe les champs « à plat » d'OTRF
(`EventID`, `Image`, `CommandLine`, `TargetFilename`, `SubjectUserName`, …) vers
vos 14 features, puis réutilise tout le pipeline (sessions → features → z-scores).

> ⚠️ Les noms de champs varient selon les captures. L'adaptateur essaie plusieurs
> variantes (insensible à la casse). Si la sortie semble vide ou bizarre, lancez
> le **diagnostic santé** dessus et envoyez-moi le résultat :
> `python -m ueba.features.health data/dataset.csv`

### 1.3 Stratégie « normal vs attaque »
- **Normal (baseline)** : prenez des captures d'activité bénigne / longues
  périodes. (Astuce : OTRF est surtout orienté *attaques* ; pour du normal
  abondant et labellisé, le **CERT Insider Threat dataset** reste le meilleur — je
  peux écrire son loader si vous voulez compléter.)
- **Attaque (test)** : les captures de techniques ATT&CK (exfiltration,
  PowerShell obfusqué, credential access) servent à mesurer la détection.
- **Métrique honnête** : taux de **faux positifs sur du normal tenu à l'écart**
  (pas sur l'entraînement) — voir `DATASET_HEALTH.md`.

### 1.4 Entraîner
Dans le notebook, cellule de config : `USE_REAL_DATA = True` → il charge
`data/dataset.csv`. La baseline figée (`baseline.json`) est exportée
automatiquement et rechargée par le daemon.

---

## Partie 2 — Démo live sur VM LOCALE (0 €)

Objectif : prouver la chaîne temps réel **une fois**, pas tourner 24/7.

### 2.1 Machines (sur votre PC)
| VM | Image | RAM conseillée | Rôle |
|----|-------|----------------|------|
| Windows | **Windows Server 2022 Evaluation** (ISO gratuit 180 j) | 4 Go | AD + Sysmon + Wazuh agent |
| Wazuh | Ubuntu 22.04 **ou** Docker | 4 Go | Manager + Indexer + Dashboard |

> Hyperviseur gratuit : VirtualBox / Hyper-V / VMware Workstation Player.
> Pas de PC assez costaud ? Faites la collecte OTRF (Partie 1) et la démo en
> **bursts GCP** (Partie 3).

### 2.2 Wazuh manager le plus simple (Docker)
```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.2
cd wazuh-docker/single-node
docker compose up -d         # Dashboard sur https://localhost:443
```

### 2.3 Sur le Windows (VM)
1. **Sysmon** avec config SwiftOnSecurity :
   ```powershell
   sysmon64.exe -accepteula -i sysmonconfig.xml
   ```
2. **Politique d'audit** (CommandLine incluse) :
   ```cmd
   auditpol /set /subcategory:"Process Creation" /success:enable
   auditpol /set /subcategory:"File System" /success:enable
   auditpol /set /subcategory:"Logon" /success:enable /failure:enable
   reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1
   ```
3. **Dossiers sensibles** + SACL d'audit :
   ```cmd
   mkdir C:\Sensitive\Finance C:\Sensitive\HR C:\Sensitive\IT
   ```
4. **Agent Wazuh** → `ossec.conf` pointe l'IP du manager local ; collecter les
   canaux `Security` et `Microsoft-Windows-Sysmon/Operational`.

### 2.4 Lancer la détection et déclencher une attaque
```bash
# sur la machine Wazuh : entraîner d'abord (notebook), copier models/ + baseline.json
python -m ueba.integration.daemon --config config/config.yaml --verbose
tail -f /var/log/ueba_alerts.json
```
Déclencher (sur le Windows, hors heures = plus suspect) :
```powershell
# Insider : exfiltration
xcopy C:\Sensitive\ D:\usb\ /E /H /C
# Malware : PowerShell obfusqué
powershell.exe -enc JABzAD0ATgBlAHcA...
# Brute force : logons échoués répétés
```
→ une alerte UEBA `HIGH/MEDIUM` doit apparaître. C'est votre démo de soutenance.

---

## Partie 3 — Discipline de coût GCP (si vous gardez le cloud)

- **VM arrêtée ≈ gratuite** : `gcloud compute instances stop NOM` quand vous ne
  collectez pas. Vous ne payez que pendant l'exécution.
- **Windows = licence facturée** par vCPU/heure → minimiser durée et vCPU.
- **Auto-extinction** (évite de saigner le crédit la nuit) :
  ```bash
  gcloud compute instances add-metadata NOM --metadata shutdown-after=4h
  # ou un cron/Cloud Scheduler qui stoppe l'instance le soir.
  ```
- Collecte réaliste en quelques heures : votre script de simulation contrôle les
  timestamps → générez des sessions réparties jour/nuit/semaine en une session de
  travail, puis **stop**.

---

## Récapitulatif
| Besoin | Solution 0–10 € |
|--------|------------------|
| Vraies données normales + labels | OTRF (attaques) **+** CERT (normal, sur demande) |
| Format Windows/Sysmon | `python -m ueba.features.otrf` (fourni) |
| Démo temps réel | VM Windows **locale** gratuite (eval 180 j) |
| Si cloud | bursts + `stop` + auto-extinction |
| Vérifier la santé des données | `python -m ueba.features.health data/dataset.csv` |

*Voir aussi `DATASET_HEALTH.md` (qualité des données) et `audit/MASTER_PLAN.md`.*
