# 🔐 PassGuard — Analyseur de Mot de Passe

Projet réalisé dans le cadre de la Licence 3 Informatique.

## Description
PassGuard est un analyseur de mot de passe côté client qui évalue 
la robustesse d'un mot de passe en temps réel et propose des 
recommandations personnalisées.

## Fonctionnalités
- Analyse en temps réel sur 8 critères (longueur, majuscules, 
  minuscules, chiffres, caractères spéciaux, patterns, entropie, 
  mots de passe courants)
- Score de 0 à 100 avec niveau de robustesse
- Estimation du temps de crack par force brute
- Recommandations personnalisées
- Générateur de mot de passe cryptographiquement sûr
- Mode clair / sombre *(si implémenté)*

## Technologies
- HTML5
- CSS3
- JavaScript (Vanilla)

## Utilisation
Aucune installation requise. Ouvrir `index.html` dans un navigateur.

## Sécurité
Tout le traitement est effectué **côté client**. 
Aucune donnée n'est envoyée sur un serveur.