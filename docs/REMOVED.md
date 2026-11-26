# Retraits et neutralisations (Android)

| Élément | Action | Statut |
|---|---|---|
| Permission INTERNET | retirée du manifeste fusionné (`tools:node="remove"`) | fait, compilé en CI, non exécuté sur téléphone |
| applicationId | `app.messagerie.mesh` (plus celui de Signal) | fait |
| Nom de l'app | « Mesh » (chaîne par défaut) | fait |
| Icône par défaut | icône neutre (vecteur + PNG) | fait |
| Icônes alternatives (activity-alias Signal) | à retirer | **non fait** |
| Workflows CI de Signal | supprimés, remplacés par `android.yml` | fait |
| Inscription par SMS, push, découverte de contacts, stockage distant, websockets, CDN, appels, paiements, stories, noms d'utilisateur, badges, dons, rapports de crash, envoi de logs | à retirer ou neutraliser | **non fait** |
| Démarrage hors ligne avec profil local | à faire | **non fait** |
