# DTLcompare

DTLcompare compare deux snapshots de diagnostic distant DTLknowsWhy : l'un collecté depuis un ordinateur où l'accès fonctionne, l'autre depuis un ordinateur où le même accès échoue.

Il produit une analyse classée qui met en évidence les différences confirmées, les causes éliminées, les causes probables, les preuves et les pistes de remédiation. Les rapports peuvent être générés en JSON, texte et HTML.

## Prérequis important : DTLknowsWhy

DTLcompare n'est pas un collecteur autonome. C'est un compagnon d'analyse pour DTLknowsWhy.

Avant de l'utiliser, il faut disposer de :

- DTLknowsWhy dans l'environnement Python ;
- le package `expert` de DTLknowsWhy importable, car `comparative_analysis.py` importe `expert.compare` ;
- deux snapshots JSON générés par les diagnostics distants de DTLknowsWhy.

Si Python ne peut pas importer `expert.compare`, DTLcompare échoue au démarrage. Lancez l'outil depuis un environnement où DTLknowsWhy est installé ou ajoutez son dossier source à `PYTHONPATH`.

## Rôle de l'outil

Le script compare les données de diagnostic distant de deux machines et cherche à expliquer pourquoi l'accès réussit d'un côté mais échoue de l'autre.

Il se concentre actuellement sur les diagnostics SMB et d'accès distant :

- incohérence de cible ;
- test de joignabilité par ping ;
- disponibilité TCP 445 ;
- différences de visibilité des partages SMB ;
- marqueurs d'échec d'authentification ;
- différences de domaine, groupe de travail ou rattachement Entra/Azure AD ;
- différences de filtres appliqués ;
- causes probables avec preuves et conseils de remédiation.

Modèle d'entrée attendu :

- `working_snapshot` : snapshot DTLknowsWhy où le test d'accès distant réussit ;
- `failing_snapshot` : snapshot DTLknowsWhy où le test équivalent échoue.

## Utilisation

```powershell
python comparative_analysis.py <working_snapshot.json> <failing_snapshot.json>
```

Exemple :

```powershell
python comparative_analysis.py 172.17.7.19_snapshot_20260610_151730.json 172.17.7.19_snapshot_20260610_152617.json
```

Par défaut, le script écrit trois rapports dans le dossier courant :

- `<prefix>.json`
- `<prefix>.txt`
- `<prefix>.html`

Il affiche aussi une synthèse lisible dans la console.

## Options

```text
--lang {fr,en}        Langue de l'analyse. Valeur par défaut : fr.
--json                Affiche aussi les constats au format JSON.
--output-prefix PATH  Préfixe des fichiers de rapport générés.
--no-files            Ne pas écrire les fichiers JSON, TXT ou HTML.
```

Exemples :

```powershell
python comparative_analysis.py ok.json ko.json --output-prefix reports/compare_ok_vs_ko
```

```powershell
python comparative_analysis.py ok.json ko.json --json --no-files
```

## Sorties

Chaque constat contient des informations structurées :

- `case` : identifiant stable du cas de diagnostic ;
- `title` : explication courte du constat ;
- `level` : niveau de gravité ou d'information ;
- `status` : cause active, éliminée ou hypothèse ;
- `confidence` : niveau de confiance ;
- `relevance_score` : score utilisé pour classer les constats ;
- `evidence` : faits extraits des snapshots ;
- `cause` : interprétation des preuves ;
- `remediation` : action suivante éventuelle.

Le rapport HTML est conçu pour être partagé avec les équipes support ou infrastructure. Le rapport JSON est plus adapté à l'automatisation ou à un traitement ultérieur.

## Notes de développement

Le point d'entrée principal est `comparative_analysis.py`.

Le script attend des structures de snapshot DTLknowsWhy et utilise des fonctions de :

```python
from expert.compare import detect_join_type
from expert.compare import get_filter_names
from expert.compare import get_path
from expert.compare import share_names
```

DTLknowsWhy et DTLcompare doivent rester alignés lorsque le schéma des snapshots évolue.

## Mise à jour - 14 juin 2026

`comparative_analysis.py` est maintenant un analyseur complet de comparaison de snapshots DTLknowsWhy.

Points importants confirmés dans le code :

- L'analyse compare un snapshot où l'accès fonctionne avec un snapshot où le même accès échoue.
- Les constats sont classés par score, gravité, statut, preuves, cause probable et remédiation.
- Le rapport inclut une conclusion lisible, les causes probables, les causes éliminées et les étapes de vérification.
- Les rapports JSON, TXT et HTML sont générés par défaut, sauf avec `--no-files`.
- `--output-prefix` permet de choisir le préfixe des fichiers générés.
- `--lang fr|en` maintient une couche d'analyse bilingue.
- Un exemple de rapport HTML est présent dans le dépôt pour valider le rendu.
