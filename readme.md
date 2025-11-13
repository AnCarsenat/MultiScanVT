# VTBatch - VirusTotal Batch File Scanner

![Version](https://img.shields.io/badge/version-1.1-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

VTBatch est une application desktop Python avec interface graphique (tkinter) permettant de scanner plusieurs fichiers simultanément via l'API VirusTotal. L'application offre une analyse détaillée des menaces, un rescannage à la demande, et la possibilité de sauvegarder votre clé API de manière sécurisée.

## 📋 Table des matières

- [Fonctionnalités](#-fonctionnalités)
- [Captures d'écran](#-captures-décran)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Utilisation](#-utilisation)
- [Obtention d'une clé API VirusTotal](#-obtention-dune-clé-api-virustotal)
- [Limitations de l'API](#-limitations-de-lapi)
- [Architecture](#-architecture)
- [Logs et débogage](#-logs-et-débogage)
- [Sécurité](#-sécurité)
- [FAQ](#-faq)
- [Licence](#-licence)

## ✨ Fonctionnalités

### Fonctionnalités principales

- 📁 **Scan batch de fichiers** - Sélectionnez et scannez plusieurs fichiers en une seule opération
- 🔐 **Sauvegarde sécurisée de la clé API** - Enregistrez votre clé API localement avec permissions restreintes
- 🔄 **Rescannage à la demande** - Demandez une nouvelle analyse pour obtenir les résultats les plus récents
- 📊 **Analyse détaillée des menaces** - Classification automatique par niveau de risque
- 🌐 **Intégration VirusTotal** - Accès direct aux rapports détaillés sur le site VirusTotal
- 📤 **Export des résultats** - Exportation des résultats au format JSON
- 📝 **Logs détaillés** - Système de logging complet pour le débogage

### Niveaux de menaces

L'application classifie automatiquement les fichiers selon leur niveau de menace :

- ✅ **Clean** - Aucune détection
- ⚡ **Suspicious** - 1 seule détection (potentiel faux positif)
- **Low Risk** - Moins de 10% de détections
- **Medium Risk** - 10-30% de détections  
- ⚠️ **High Risk** - Plus de 30% de détections

### Interface utilisateur

- 🎨 Interface intuitive avec onglets multiples
- 📈 Barre de progression en temps réel
- 🔍 Double-clic pour ouvrir les rapports VirusTotal
- 🎯 Affichage en tableau avec tri et colonnes redimensionnables
- 💾 Sauvegarde automatique des logs

## 📸 Captures d'écran

L'application comprend trois onglets principaux :

1. **Scanner** - Sélection de fichiers et lancement des scans
2. **Results** - Visualisation des résultats avec actions rapides
3. **Debug Logs** - Logs détaillés de l'application

## 🔧 Installation

### Pour Windows

Naviguez dans la section `Releases` et téléchargez la dernière version (fichier `.zip` ou `MultiScanVT.exe`). Extrayez l'archive si nécessaire, puis exécutez l'application (.exe)

### Prérequis

- Python 3.7 ou supérieur
- pip (gestionnaire de paquets Python)
- Connexion Internet
- Clé API VirusTotal (gratuite ou premium)

### Installation des dépendances

```bash
# Cloner ou télécharger le projet
git clone https://github.com/votre-repo/vtbatch.git
cd vtbatch

# Installer les dépendances requises
pip install -r requirements.txt
```

### Contenu du fichier requirements.txt

```
requests>=2.28.0
pillow>=9.0.0
```

**Note :** tkinter est inclus par défaut avec Python sur la plupart des systèmes.

### Installation manuelle des dépendances

```bash
pip install requests pillow
```

### Vérification de tkinter

Sur certains systèmes Linux, tkinter peut nécessiter une installation séparée :

```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# Fedora
sudo dnf install python3-tkinter

# Arch Linux
sudo pacman -S tk
```

## ⚙️ Configuration

### Premier lancement

1. Lancez l'application :
   ```bash
   python vtbatch.py
   ```

2. Dans l'onglet **Scanner**, entrez votre clé API VirusTotal

3. Cochez la case **"Save"** pour sauvegarder la clé (optionnel mais recommandé)

4. Cliquez sur **"Test API Key"** pour valider la clé

### Sauvegarde de la clé API

Lorsque vous cochez la case "Save", la clé API est stockée dans :
- **Linux/macOS** : `~/.vtbatch/config.json`
- **Windows** : `C:\Users\VotreNom\.vtbatch\config.json`

Le fichier est créé avec des permissions restrictives (lecture/écriture propriétaire uniquement sur Unix).

### Effacer la clé sauvegardée

Pour supprimer la clé API sauvegardée :
1. Cliquez sur le bouton **"Clear Saved Key"**
2. Confirmez l'action dans la boîte de dialogue

## 🚀 Utilisation

### Workflow de base

1. **Configurer l'API**
   - Entrez votre clé API VirusTotal
   - Testez la clé pour confirmer qu'elle est valide
   - Optionnellement, sauvegardez-la pour les sessions futures

2. **Sélectionner les fichiers**
   - Cliquez sur **"Select Files"**
   - Choisissez un ou plusieurs fichiers à scanner
   - Les fichiers apparaissent dans la liste

3. **Lancer le scan**
   - Cliquez sur **"Start Scan"**
   - La barre de progression indique l'avancement
   - Les résultats apparaissent au fur et à mesure dans l'onglet **Results**

4. **Analyser les résultats**
   - Consultez les détections pour chaque fichier
   - Double-cliquez sur une ligne pour voir le rapport complet sur VirusTotal
   - Utilisez **"Rescan Selected"** pour demander une nouvelle analyse

5. **Exporter (optionnel)**
   - Cliquez sur **"Export Results"** pour sauvegarder les résultats en JSON

### Fonctionnalités avancées

#### Rescannage de fichiers

Pour obtenir une analyse à jour d'un fichier déjà scanné :

1. Sélectionnez le fichier dans l'onglet **Results**
2. Cliquez sur **"Rescan Selected"**
3. Confirmez la demande de rescannage
4. Attendez que la nouvelle analyse soit complète (30-60 secondes)

**Note :** Le rescannage soumet à nouveau le fichier à tous les moteurs antivirus de VirusTotal.

#### Visualisation des rapports détaillés

Plusieurs méthodes pour accéder aux rapports VirusTotal :

- Double-cliquez sur une ligne dans les résultats
- Sélectionnez une ligne et cliquez sur **"Open in VirusTotal"**
- Le rapport s'ouvre dans votre navigateur par défaut

#### Export des résultats

Le fichier JSON exporté contient :
```json
{
  "scan_date": "2025-11-13T...",
  "total_files": 5,
  "results": [
    {
      "filename": "example.exe",
      "file_path": "/path/to/file",
      "sha256": "hash...",
      "detections": 3,
      "total_scans": 70,
      "threat_level": "low_risk",
      "suspicious_vendors": ["Vendor1", "Vendor2"],
      "malware_types": ["trojan", "malware"]
    }
  ]
}
```

## 🔑 Obtention d'une clé API VirusTotal

### Compte gratuit

1. Créez un compte sur [VirusTotal](https://www.virustotal.com/)
2. Connectez-vous à votre compte
3. Accédez à votre profil (icône utilisateur en haut à droite)
4. Cliquez sur **"API Key"** dans le menu
5. Copiez votre clé API

### Limitations du compte gratuit

- **4 requêtes par minute** maximum
- **500 requêtes par jour**
- **32 MB** taille maximale par fichier
- Accès à l'API publique v2

**Note :** VTBatch intègre automatiquement des délais (15 secondes entre chaque scan) pour respecter les limites du compte gratuit.

### Compte premium

Les comptes premium offrent :
- Taux de requêtes plus élevés
- Taille de fichiers plus importante
- Accès à des fonctionnalités avancées
- API v3 avec plus de détails

Pour plus d'informations : [VirusTotal Premium](https://www.virustotal.com/gui/my-apikey)

## ⚠️ Limitations de l'API

### Rate Limiting (compte gratuit)

VTBatch gère automatiquement les limitations :
- **15 secondes** d'attente entre chaque scan
- **10 secondes** d'attente avant de récupérer un rapport
- **Retry logic** avec 3 tentatives en cas d'erreur

### Calcul du temps de scan

Pour **n fichiers** avec un compte gratuit :
```
Temps estimé = n × 25 secondes (scan + analyse + délai)
```

Exemples :
- 5 fichiers ≈ 2 minutes
- 10 fichiers ≈ 4 minutes
- 20 fichiers ≈ 8 minutes

### Dépassement des limites

Si vous dépassez les limites de l'API :
- Message d'erreur explicite dans les logs
- Le scan s'arrête automatiquement
- Les résultats partiels sont conservés
- Attendez 1 minute avant de relancer

## 🏗️ Architecture

### Structure du code

```
vtbatch.py
├── ConfigManager          # Gestion de la configuration et clé API
├── VirusTotalAPI         # Wrapper API VirusTotal
│   ├── scan_file()       # Upload et scan
│   ├── get_report()      # Récupération des rapports
│   └── rescan_file()     # Demande de rescannage
├── FileScanner           # Logique d'analyse
│   ├── calculate_file_hash()  # Calcul MD5, SHA1, SHA256
│   └── analyze_results()      # Analyse des menaces
└── VirusTotalGUI         # Interface graphique
    ├── Scanner Tab       # Sélection et scan
    ├── Results Tab       # Affichage des résultats
    └── Logs Tab          # Logs de débogage
```

### Threading

L'application utilise des threads pour :
- Éviter le gel de l'interface pendant les scans
- Permettre l'annulation des opérations en cours
- Traiter les messages asynchrones via une queue

### Gestion des erreurs

- **Retry logic** automatique pour les erreurs réseau
- **Validation JSON** des réponses API
- **Logging détaillé** de toutes les erreurs
- **Messages utilisateur** clairs et informatifs

## 📝 Logs et débogage

### Fichiers de logs

Les logs sont automatiquement sauvegardés dans :
```
virustotal_scanner.log
```

### Niveaux de log

- **INFO** - Opérations normales (scans, uploads)
- **WARNING** - Situations inhabituelles mais gérables
- **ERROR** - Erreurs nécessitant attention

### Consultation des logs

1. Onglet **Debug Logs** dans l'application
2. Auto-scroll pour suivre en temps réel
3. Bouton **"Save Logs"** pour exporter
4. Bouton **"Clear Logs"** pour nettoyer l'affichage

### Logs utiles pour le débogage

```
2025-11-13 10:30:15 - INFO - API key validated successfully
2025-11-13 10:30:20 - INFO - Uploading file: example.exe
2025-11-13 10:30:25 - INFO - Upload successful for example.exe
2025-11-13 10:30:35 - INFO - Analysis complete: 3/70 detections
```

## 🔒 Sécurité

### Stockage de la clé API

- Fichier JSON local avec permissions restrictives
- Pas de transmission en clair (utilise HTTPS pour l'API)
- Possibilité de ne pas sauvegarder (saisie à chaque session)

### Recommandations

1. **Ne partagez jamais** votre clé API
2. **Révoquéz** votre clé si elle est compromise
3. **Utilisez un compte dédié** pour les scans automatisés
4. **Vérifiez les fichiers** avant de les scanner (droits, source)

### Fichiers scannés

- Les fichiers sont **uploadés temporairement** sur VirusTotal
- VirusTotal conserve les fichiers pour analyse communautaire
- **Ne scannez pas de fichiers confidentiels** avec un compte gratuit
- Les hashes sont publics sur VirusTotal

### Permissions système

Sur Unix/Linux, le fichier de configuration reçoit les permissions `600` :
```bash
-rw------- 1 user user  config.json
```

## ❓ FAQ

### Le scan est très lent, est-ce normal ?

Oui, avec un compte gratuit, VTBatch respecte la limite de 4 requêtes/minute. Comptez environ 25 secondes par fichier.

### Puis-je scanner plus de 500 fichiers par jour ?

Non avec un compte gratuit. Passez à un compte premium pour des quotas plus élevés.

### Pourquoi certains fichiers montrent "Error" ?

Causes possibles :
- Fichier trop volumineux (>32 MB en gratuit)
- Timeout réseau
- Limite de l'API atteinte
- Format de fichier non supporté

Consultez les logs pour plus de détails.

### Comment interpréter les résultats ?

- **0 détections** = Clean (fichier sain)
- **1-2 détections** = Possible faux positif
- **3-10 détections** = Fichier suspect, vérifiez la source
- **10+ détections** = Très probablement malveillant

### Mon antivirus bloque l'application, pourquoi ?

Certains antivirus peuvent détecter VTBatch comme suspect car il interagit avec des fichiers et utilise des APIs réseau. Ajoutez une exception si vous faites confiance au code source.

### Puis-je scanner des dossiers entiers ?

Actuellement non. Vous devez sélectionner les fichiers individuellement. Une future version pourrait inclure cette fonctionnalité.

### Le rescannage donne des résultats différents ?

Oui, c'est normal. Les bases de données antivirus sont mises à jour régulièrement. Un rescannage peut détecter de nouvelles menaces ou éliminer des faux positifs.

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier LICENSE pour plus de détails.

```
MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🤝 Contribution

Les contributions sont les bienvenues ! Pour contribuer :

1. Fork le projet
2. Créez une branche pour votre fonctionnalité (`git checkout -b feature/AmazingFeature`)
3. Committez vos changements (`git commit -m 'Add some AmazingFeature'`)
4. Push vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrez une Pull Request

## 📧 Support

Pour toute question ou problème :
- Ouvrez une issue sur GitHub
- Consultez les logs de débogage
- Vérifiez votre clé API et votre connexion Internet

## 🙏 Remerciements

- [VirusTotal](https://www.virustotal.com/) pour leur excellente API
- La communauté Python pour tkinter et les bibliothèques utilisées
- Tous les contributeurs au projet

---

**⚠️ Avertissement** : VTBatch est fourni "tel quel" sans garantie. L'auteur n'est pas responsable de l'utilisation qui en est faite. Utilisez toujours plusieurs sources pour évaluer la sécurité d'un fichier.