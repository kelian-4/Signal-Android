# Tests à faire sur téléphones (non vérifiables en CI)

Rien de ce tableau n'a été exécuté : le Bluetooth, la batterie et l'arrière-plan ne se testent que sur matériel.
Les diagnostics sont écrits dans `files/mesh-link-diag.csv` (colonnes : t_ms, event, thermal, main_block_ms,
disconnect_code, rssi, battery_pct, screen_locked).

| # | Test | Matériel | Résultat attendu | À relever |
|---|------|----------|------------------|-----------|
| 1 | Découverte | 2 téléphones, écran allumé, à 1 m | « link_up » dans le CSV en moins de 15 s après un envoi | délai de découverte, RSSI |
| 2 | Latence | 2 téléphones, 20 messages de 50 octets | ACK de bout en bout reçu pour chacun | latence médiane et p95 |
| 3 | Gros message | 2 téléphones, texte de 4 Ko | réassemblage correct, aucun doublon | nombre de trames, durée |
| 4 | Arrière-plan | app en arrière-plan, écran verrouillé 10 min | le message envoyé est reçu | `screen_locked`, codes de déconnexion |
| 5 | App balayée | balayer l'app des récents puis envoyer | message reçu quand le service au premier plan tourne | service relancé ? notification visible ? |
| 6 | Nuit | 2 téléphones branchés, 8 h, 1 message/10 min | 0 message perdu, outbox vide au matin | `link_down`, `watchdog_repair_*`, thermique |
| 7 | Batterie | 2 téléphones débranchés, 8 h, mêmes conditions | consommation documentée | `battery_pct` par heure |
| 8 | Relais à 2 sauts | A — C — B, A et B hors de portée l'un de l'autre | B reçoit, C n'affiche rien | TTL restant, temps de bout en bout |
| 9 | Gel de l'app | geler un téléphone ~45 s (mode économie extrême) | réparation par le watchdog, aucun message coincé | `main_block_ms`, `watchdog_repair_*` |
| 10 | Erreur 133 | s'éloigner/revenir, Bluetooth on/off | reconnexion avec backoff, pas de boucle | codes 133 dans le CSV |
| 11 | Exemption batterie | accepter puis refuser la demande système | comportement comparé avec/sans exemption | durée avant coupure du lien |
| 12 | Clé qui change | réinstaller l'app sur un téléphone | alerte et badge « vérifié » retiré chez l'autre | — |
| 13 | Restauration | effacer l'app, restaurer par la phrase de 24 mots | même identité, historique importé depuis la sauvegarde | sessions renégociées |
