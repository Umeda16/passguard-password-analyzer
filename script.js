/**
 * Analyseur de Mot de Passe — script.js
 * Projet L3 Informatique
 *
 * Architecture :
 *   1. Constantes & données
 *   2. Fonctions d'analyse pures (sans accès au DOM)
 *   3. Couche DOM (cache, listeners, rendu)
 *   4. Initialisation
 */

'use strict';

/* ============================================================
   1. CONSTANTES & DONNÉES
   ============================================================ */

/** Mots de passe et mots courants à détecter */
const COMMON_WORDS = [
  'password', 'motdepasse', 'mdp', 'passw0rd', 'pa$$word',
  'bonjour', 'soleil', 'iloveyou', 'jetaime', 'amour',
  'qwerty', 'azerty', 'qwertyuiop', 'azertyuiop',
  'admin', 'administrateur', 'root', 'user', 'utilisateur',
  '123456', '1234567', '12345678', '123456789', '1234567890',
  'letmein', 'welcome', 'bienvenue', 'dragon', 'master',
  'sunshine', 'princess', 'football', 'monkey', 'batman',
  'superman', 'pokemon', 'naruto', 'minecraft',
  'abc123', 'abc', 'test', 'demo', 'temp', 'login',
  'pass', 'secret', 'changeme', 'default', 'azerty123',
  'motdepasse123', 'france', 'paris', 'marseille',
];

/** Lignes de clavier pour la détection de séquences */
const KEYBOARD_ROWS = [
  'qwertyuiop',
  'asdfghjkl',
  'zxcvbnm',
  'azertyuiop',
  'qsdfghjklm',
  'wxcvbn',
  '1234567890',
];

/**
 * Taille des pools de caractères pour le calcul d'entropie.
 * Modèle Shannon (pooled-charset) : H = L × log₂(N)
 * Note : ce modèle surestime l'entropie pour les mots de passe
 * prévisibles — c'est pourquoi la détection de patterns existe
 * en couche séparée pour pénaliser le score.
 */
const CHARSET_SIZES = {
  lower:   26,
  upper:   26,
  digit:   10,
  special: 32,
};

/**
 * Vitesse d'attaque simulée : 10 milliards de guesses/seconde.
 * Représente un cluster GPU avec un hash rapide non salé (ex: MD5).
 * C'est un scénario pessimiste réaliste — un hash moderne (bcrypt)
 * serait ~100 000 fois plus lent.
 */
const GUESSES_PER_SECOND = 1e10;

/** Labels français pour les niveaux de force */
const LEVEL_LABELS = {
  'tres-faible': 'Très faible',
  'faible':      'Faible',
  'moyen':       'Moyen',
  'fort':        'Fort',
  'tres-fort':   'Très fort',
};

/* ============================================================
   2. FONCTIONS D'ANALYSE PURES
   ============================================================ */

/**
 * Lance les 8 vérifications de base sur le mot de passe.
 * @param {string} pw
 * @returns {Object} — 8 booléens
 */
function runChecks(pw) {
  return {
    hasMinLength:     pw.length >= 12,
    hasUpper:         /[A-Z]/.test(pw),
    hasLower:         /[a-z]/.test(pw),
    hasDigit:         /[0-9]/.test(pw),
    hasSpecial:       /[^A-Za-z0-9]/.test(pw),
    noRepeatedChars:  !/(.)(\1{2,})/u.test(pw),
    noKeyboardWalk:   !detectKeyboardWalk(pw),
    noCommonPattern:  !detectCommonWordOrDate(pw),
  };
}

/**
 * Détecte les séquences de clavier (fenêtre glissante de 4 chars).
 * @param {string} pw
 * @returns {boolean}
 */
function detectKeyboardWalk(pw) {
  const lower = pw.toLowerCase();
  for (const row of KEYBOARD_ROWS) {
    const reversed = row.split('').reverse().join('');
    for (let i = 0; i <= lower.length - 4; i++) {
      const chunk = lower.slice(i, i + 4);
      if (row.includes(chunk) || reversed.includes(chunk)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Détecte les mots courants et les dates.
 * @param {string} pw
 * @returns {boolean}
 */
function detectCommonWordOrDate(pw) {
  const lower = pw.toLowerCase();

  // Mots courants
  if (COMMON_WORDS.some(word => lower.includes(word))) return true;

  // Dates complètes : 14/07/1989, 01-01-2000, 2024-12-31
  if (/\b(0?[1-9]|[12]\d|3[01])[\/\-](0?[1-9]|1[0-2])[\/\-]?\d{2,4}\b/.test(pw)) return true;

  // Années seules : 1900–2029
  if (/\b(19|20)\d{2}\b/.test(pw)) return true;

  return false;
}

/**
 * Détecte et liste tous les patterns problématiques.
 * @param {string} pw
 * @returns {string[]} — Messages d'avertissement en français
 */
function detectPatterns(pw) {
  const warnings = [];
  const lower = pw.toLowerCase();

  // Répétitions de caractères (3+)
  if (/(.)(\1{2,})/u.test(pw)) {
    warnings.push('Caractères répétés consécutivement détectés (ex : aaa, 111)');
  }

  // Séquences de clavier
  if (detectKeyboardWalk(pw)) {
    warnings.push('Séquence de clavier détectée (ex : azerty, qwerty, asdf)');
  }

  // Date complète
  if (/\b(0?[1-9]|[12]\d|3[01])[\/\-](0?[1-9]|1[0-2])[\/\-]?\d{2,4}\b/.test(pw)) {
    warnings.push('Date détectée — les dates personnelles sont facilement devinables');
  }

  // Année seule
  if (/\b(19|20)\d{2}\b/.test(pw)) {
    warnings.push('Année détectée dans le mot de passe (ex : 1998, 2024)');
  }

  // Mot de passe courant
  if (COMMON_WORDS.some(word => lower.includes(word))) {
    warnings.push('Mot ou expression trop courant(e) détecté(e) dans le mot de passe');
  }

  // Séquences de chiffres croissantes/décroissantes
  if (/0123|1234|2345|3456|4567|5678|6789|7890|9876|8765|7654|6543|5432|4321|3210/.test(pw)) {
    warnings.push('Séquence numérique trop prévisible (ex : 1234, 9876)');
  }

  return warnings;
}

/**
 * Calcule la taille du pool de caractères utilisés.
 * @param {string} pw
 * @returns {number}
 */
function getCharsetSize(pw) {
  let size = 0;
  if (/[a-z]/.test(pw)) size += CHARSET_SIZES.lower;
  if (/[A-Z]/.test(pw)) size += CHARSET_SIZES.upper;
  if (/[0-9]/.test(pw)) size += CHARSET_SIZES.digit;
  if (/[^A-Za-z0-9]/.test(pw)) size += CHARSET_SIZES.special;
  return size || 1;
}

/**
 * Calcule l'entropie théorique en bits : H = L × log₂(N).
 * @param {string} pw
 * @returns {number}
 */
function calculateEntropy(pw) {
  if (!pw) return 0;
  const N = getCharsetSize(pw);
  return Math.round(pw.length * Math.log2(N));
}

/**
 * Formate un nombre de secondes en durée lisible en français.
 * Utilise l'entropie directement pour les très grandes valeurs
 * afin d'éviter l'overflow de Number.
 * @param {number} entropy — bits d'entropie
 * @returns {string}
 */
function formatCrackTime(entropy) {
  if (entropy <= 0) return 'instantané';

  // Nombre de guesses attendu (cas moyen) = 2^(entropy-1)
  // On travaille en log pour éviter l'overflow
  const logGuesses = (entropy - 1) * Math.log10(2); // log10(2^(H-1))
  const logSeconds = logGuesses - Math.log10(GUESSES_PER_SECOND);

  if (logSeconds < 0)   return 'moins d\'une seconde';
  if (logSeconds < Math.log10(60))    return `${Math.round(Math.pow(10, logSeconds))} seconde(s)`;
  if (logSeconds < Math.log10(3600))  return `${Math.round(Math.pow(10, logSeconds) / 60)} minute(s)`;
  if (logSeconds < Math.log10(86400)) return `${Math.round(Math.pow(10, logSeconds) / 3600)} heure(s)`;

  const logDays = logSeconds - Math.log10(86400);
  if (logDays < Math.log10(30))   return `${Math.round(Math.pow(10, logDays))} jour(s)`;
  if (logDays < Math.log10(365))  return `${Math.round(Math.pow(10, logDays) / 30)} mois`;

  const logYears = logDays - Math.log10(365);
  if (logYears < 3)  return `${Math.round(Math.pow(10, logYears))} an(s)`;
  if (logYears < 6)  return `${Math.round(Math.pow(10, logYears - 3))} millier(s) d'années`;
  if (logYears < 9)  return `${Math.round(Math.pow(10, logYears - 6))} million(s) d'années`;
  if (logYears < 12) return `${Math.round(Math.pow(10, logYears - 9))} milliard(s) d'années`;
  return 'des billions d\'années (pratiquement incassable)';
}

/**
 * Calcule un score de 0 à 100 de façon additive avec pénalités.
 * @param {string} pw
 * @param {Object} checks
 * @param {string[]} patterns
 * @param {number} entropy
 * @returns {number}
 */
function computeScore(pw, checks, patterns, entropy) {
  let score = 0;
  const len = pw.length;

  // Points pour la longueur
  if (len >= 16)      score += 50;
  else if (len >= 12) score += 35;
  else if (len >= 8)  score += 20;
  else if (len >= 6)  score += 10;
  else if (len >= 1)  score += 5;

  // Points pour la diversité des caractères
  if (checks.hasLower)   score += 5;
  if (checks.hasUpper)   score += 10;
  if (checks.hasDigit)   score += 10;
  if (checks.hasSpecial) score += 15;

  // Points pour l'absence de patterns mauvais
  if (checks.noRepeatedChars)  score += 5;
  if (checks.noKeyboardWalk)   score += 5;

  // Bonus entropie élevée
  if (entropy > 60) score += 5;

  // Pénalités pour chaque pattern détecté
  score -= patterns.length * 10;

  // Pénalité forte si mot courant
  if (!checks.noCommonPattern) score -= 10;

  // Plafond dur si trop court
  if (len < 6) score = Math.min(score, 15);
  if (len < 4) score = Math.min(score, 5);

  return Math.max(0, Math.min(100, score));
}

/**
 * Convertit un score en niveau de force.
 * @param {number} score
 * @returns {string}
 */
function scoreToLevel(score) {
  if (score >= 80) return 'tres-fort';
  if (score >= 60) return 'fort';
  if (score >= 40) return 'moyen';
  if (score >= 20) return 'faible';
  return 'tres-faible';
}

/**
 * Compte le score de diversité sur 5 critères.
 * @param {string} pw
 * @param {Object} checks
 * @returns {number} 0–5
 */
function calculateDiversity(pw, checks) {
  let d = 0;
  if (checks.hasLower)   d++;
  if (checks.hasUpper)   d++;
  if (checks.hasDigit)   d++;
  if (checks.hasSpecial) d++;
  if (pw.length >= 12)   d++;
  return d;
}

/**
 * Construit la liste de recommandations contextuelles.
 * @param {Object} checks
 * @param {string[]} patterns
 * @param {number} entropy
 * @param {number} len
 * @returns {string[]}
 */
function buildRecommendations(checks, patterns, entropy, len) {
  const recs = [];

  if (!checks.hasMinLength) {
    recs.push(len < 8
      ? 'Utilisez au moins 12 caractères — plus c\'est long, plus c\'est sûr.'
      : 'Allongez votre mot de passe à 12 caractères minimum (idéalement 16+).'
    );
  }

  if (!checks.hasUpper) {
    recs.push('Ajoutez au moins une lettre majuscule (A–Z) pour augmenter le pool.');
  }

  if (!checks.hasLower) {
    recs.push('Incluez des lettres minuscules (a–z).');
  }

  if (!checks.hasDigit) {
    recs.push('Intégrez des chiffres (0–9) pour diversifier les caractères.');
  }

  if (!checks.hasSpecial) {
    recs.push('Ajoutez des caractères spéciaux : ! @ # $ % & * ( ) _ + - = ? …');
  }

  if (!checks.noRepeatedChars) {
    recs.push('Évitez de répéter le même caractère plusieurs fois de suite (aaa, 111).');
  }

  if (!checks.noKeyboardWalk) {
    recs.push('Évitez les séquences de touches clavier (azerty, qwerty, asdf, hjkl…).');
  }

  if (!checks.noCommonPattern) {
    recs.push('Évitez les mots courants, prénoms, noms et dates personnelles.');
  }

  if (entropy < 40 && len > 0) {
    recs.push('Augmentez la longueur et diversifiez les types de caractères pour améliorer l\'entropie.');
  }

  if (patterns.some(p => p.includes('date') || p.includes('Année'))) {
    recs.push('Les dates de naissance ou anniversaires sont les premières choses testées par les attaquants.');
  }

  // Conseil général si le mot de passe est déjà très fort
  if (recs.length === 0) {
    recs.push('Excellent ! Votre mot de passe semble robuste. Pensez à utiliser un gestionnaire de mots de passe pour le stocker en sécurité.');
    recs.push('Activez l\'authentification à deux facteurs (2FA) sur vos comptes importants.');
    recs.push('N\'utilisez jamais le même mot de passe sur plusieurs services.');
  }

  return recs;
}

/**
 * Point d'entrée de l'analyse. Retourne un objet résultat complet.
 * @param {string} pw
 * @returns {Object}
 */
function analyzePassword(pw) {
  const checks   = runChecks(pw);
  const patterns = detectPatterns(pw);
  const entropy  = calculateEntropy(pw);
  const score    = computeScore(pw, checks, patterns, entropy);
  const level    = scoreToLevel(score);
  const diversity = calculateDiversity(pw, checks);
  const crackTime = formatCrackTime(entropy);
  const recommendations = buildRecommendations(checks, patterns, entropy, pw.length);

  return { checks, patterns, entropy, score, level, diversity, crackTime, recommendations };
}

/* ============================================================
   3. COUCHE DOM
   ============================================================ */

/** Cache des éléments DOM */
const dom = {};

/** Icônes SVG inline */
const ICONS = {
  eye: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24"
        fill="none" stroke="currentColor" stroke-width="2"
        stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
        <circle cx="12" cy="12" r="3"/>
      </svg>`,

  eyeOff: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24"
           fill="none" stroke="currentColor" stroke-width="2"
           stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
           <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8
                    a18.45 18.45 0 0 1 5.06-5.94"/>
           <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8
                    a18.5 18.5 0 0 1-2.16 3.19"/>
           <line x1="1" y1="1" x2="23" y2="23"/>
         </svg>`,

  sun: `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24"
        fill="none" stroke="currentColor" stroke-width="2"
        stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <circle cx="12" cy="12" r="5"/>
        <line x1="12" y1="1" x2="12" y2="3"/>
        <line x1="12" y1="21" x2="12" y2="23"/>
        <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>
        <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
        <line x1="1" y1="12" x2="3" y2="12"/>
        <line x1="21" y1="12" x2="23" y2="12"/>
        <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>
        <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
      </svg>`,

  moon: `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24"
         fill="none" stroke="currentColor" stroke-width="2"
         stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
         <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
       </svg>`,

  check: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24"
          fill="none" stroke="currentColor" stroke-width="3"
          stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <polyline points="20 6 9 17 4 12"/>
        </svg>`,

  cross: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24"
          fill="none" stroke="currentColor" stroke-width="3"
          stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <line x1="18" y1="6" x2="6" y2="18"/>
          <line x1="6" y1="6" x2="18" y2="18"/>
        </svg>`,

  warning: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2.5"
            stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3
                     L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/>
            <line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>`,

  lightbulb: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24"
              fill="none" stroke="currentColor" stroke-width="2"
              stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <line x1="9" y1="18" x2="15" y2="18"/>
              <line x1="10" y1="22" x2="14" y2="22"/>
              <path d="M15.09 14c.18-.98.65-1.74 1.41-2.5A4.65 4.65 0 0 0 18 8
                       6 6 0 0 0 6 8c0 1 .23 2.23 1.5 3.5A4.61 4.61 0 0 1 8.91 14"/>
            </svg>`,
};

/** Mapping critère → clé dans checks */
const CRIT_KEYS = {
  'crit-length':   'hasMinLength',
  'crit-upper':    'hasUpper',
  'crit-lower':    'hasLower',
  'crit-digit':    'hasDigit',
  'crit-special':  'hasSpecial',
  'crit-repeat':   'noRepeatedChars',
  'crit-keyboard': 'noKeyboardWalk',
  'crit-common':   'noCommonPattern',
};

/**
 * Met en cache les références DOM.
 */
function cacheElements() {
  dom.input          = document.getElementById('password-input');
  dom.fill           = document.getElementById('strength-bar-fill');
  dom.strengthLabel  = document.getElementById('strength-label');
  dom.entropyValue   = document.getElementById('entropy-value');
  dom.crackTime      = document.getElementById('crack-time');
  dom.diversityScore = document.getElementById('diversity-score');
  dom.criteriaItems  = document.querySelectorAll('.criteria-item');
  dom.patternWarnings= document.getElementById('pattern-warnings');
  dom.recoToggle     = document.getElementById('reco-toggle');
  dom.recoPanel      = document.getElementById('reco-panel');
  dom.recoList       = document.getElementById('reco-list');
  dom.themeToggle    = document.getElementById('theme-toggle');
  dom.visToggle      = document.getElementById('visibility-toggle');
  dom.copyBtn        = document.getElementById('copy-btn');
}

/**
 * Attache tous les écouteurs d'événements.
 */
function attachListeners() {
  dom.input.addEventListener('input', triggerAnalysis);
  dom.visToggle.addEventListener('click', toggleVisibility);
  dom.copyBtn.addEventListener('click', copyPassword);
  dom.themeToggle.addEventListener('click', toggleTheme);
  dom.recoToggle.addEventListener('click', toggleRecommendations);
}

/* ── Handlers ── */

function triggerAnalysis() {
  const pw = dom.input.value;
  if (!pw) {
    resetUI();
    return;
  }
  const result = analyzePassword(pw);
  updateUI(result);
}

let visiblePassword = false;

function toggleVisibility() {
  visiblePassword = !visiblePassword;
  dom.input.type = visiblePassword ? 'text' : 'password';
  dom.visToggle.setAttribute('aria-label',
    visiblePassword ? 'Masquer le mot de passe' : 'Afficher le mot de passe'
  );
  dom.visToggle.innerHTML = visiblePassword ? ICONS.eyeOff : ICONS.eye;
}

function copyPassword() {
  const pw = dom.input.value;
  if (!pw) return;

  const doCopy = () => {
    dom.copyBtn.classList.add('copied');
    setTimeout(() => dom.copyBtn.classList.remove('copied'), 1500);
  };

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(pw).then(doCopy).catch(() => fallbackCopy(pw, doCopy));
  } else {
    fallbackCopy(pw, doCopy);
  }
}

function fallbackCopy(text, callback) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.cssText = 'position:fixed;left:-9999px;top:-9999px;opacity:0';
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  try {
    document.execCommand('copy');
    callback();
  } catch (e) {
    // Copie non supportée — on ignore silencieusement
  }
  document.body.removeChild(ta);
}

function toggleTheme() {
  const body = document.body;
  const current = body.getAttribute('data-theme');
  const next = current === 'light' ? 'dark' : 'light';
  body.setAttribute('data-theme', next);
  localStorage.setItem('mdp-theme', next);
  dom.themeToggle.setAttribute('aria-pressed', next === 'light');
  dom.themeToggle.setAttribute('aria-label',
    next === 'light' ? 'Basculer vers le mode sombre' : 'Basculer vers le mode clair'
  );
  dom.themeToggle.innerHTML = next === 'light' ? ICONS.sun : ICONS.moon;
}

function toggleRecommendations() {
  const isOpen = dom.recoToggle.getAttribute('aria-expanded') === 'true';
  dom.recoToggle.setAttribute('aria-expanded', String(!isOpen));
  dom.recoPanel.classList.toggle('open', !isOpen);
}

/* ── Fonctions de rendu ── */

function updateUI(result) {
  updateStrengthBar(result.score, result.level);
  updateStrengthLabel(result.level);
  updateMetrics(result.entropy, result.crackTime, result.diversity);
  updateCriteriaList(result.checks);
  updatePatternWarnings(result.patterns);
  updateRecommendations(result.recommendations);
}

function updateStrengthBar(score, level) {
  const fill = dom.fill;

  // Détermine la couleur via le niveau
  const colorMap = {
    'tres-faible': 'var(--color-very-weak)',
    'faible':      'var(--color-weak)',
    'moyen':       'var(--color-fair)',
    'fort':        'var(--color-strong)',
    'tres-fort':   'var(--color-very-strong)',
  };

  fill.style.width           = `${score}%`;
  fill.style.backgroundColor = colorMap[level] || 'var(--color-very-weak)';
  fill.setAttribute('aria-valuenow', score);

  // Effet pulse à chaque mise à jour
  fill.classList.remove('pulse');
  void fill.offsetWidth; // force reflow pour relancer l'animation
  fill.classList.add('pulse');
}

function updateStrengthLabel(level) {
  const label = dom.strengthLabel;
  // Supprime toutes les classes de niveau
  label.className = 'strength-label';
  label.classList.add(`level-${level}`);
  label.textContent = LEVEL_LABELS[level] || '—';
}

function updateMetrics(entropy, crackTime, diversity) {
  dom.entropyValue.textContent   = `${entropy} bits`;
  dom.crackTime.textContent      = crackTime;
  dom.diversityScore.textContent = `${diversity} / 5`;
}

function updateCriteriaList(checks) {
  dom.criteriaItems.forEach(item => {
    const critId  = item.id;
    const key     = CRIT_KEYS[critId];
    const passed  = key ? checks[key] : false;

    item.classList.toggle('pass', passed);
    item.classList.toggle('fail', !passed);

    const iconEl = item.querySelector('.crit-icon');
    if (iconEl) {
      iconEl.innerHTML = passed ? ICONS.check : ICONS.cross;
    }

    item.setAttribute('aria-label',
      item.querySelector('span:last-child').textContent +
      (passed ? ' — validé' : ' — non validé')
    );
  });
}

function updatePatternWarnings(patterns) {
  dom.patternWarnings.innerHTML = '';
  patterns.forEach(msg => {
    const badge = document.createElement('div');
    badge.className = 'warning-badge';
    badge.innerHTML = `<span class="crit-icon">${ICONS.warning}</span><span>${msg}</span>`;
    dom.patternWarnings.appendChild(badge);
  });
}

function updateRecommendations(recs) {
  dom.recoList.innerHTML = '';
  recs.forEach(rec => {
    const li = document.createElement('li');
    li.className = 'reco-item';
    li.innerHTML = `<span class="reco-icon">${ICONS.lightbulb}</span><span>${rec}</span>`;
    dom.recoList.appendChild(li);
  });
}

/**
 * Réinitialise l'interface quand le champ est vide.
 */
function resetUI() {
  dom.fill.style.width           = '0%';
  dom.fill.style.backgroundColor = '';
  dom.fill.setAttribute('aria-valuenow', 0);

  dom.strengthLabel.className    = 'strength-label';
  dom.strengthLabel.textContent  = '—';

  dom.entropyValue.textContent   = '— bits';
  dom.crackTime.textContent      = '—';
  dom.diversityScore.textContent = '0 / 5';

  dom.criteriaItems.forEach(item => {
    item.classList.remove('pass', 'fail');
    const iconEl = item.querySelector('.crit-icon');
    if (iconEl) iconEl.innerHTML = '';
  });

  dom.patternWarnings.innerHTML = '';
  dom.recoList.innerHTML        = '';
}

/**
 * Applique le thème sauvegardé au chargement.
 */
function loadTheme() {
  const saved = localStorage.getItem('mdp-theme') || 'dark';
  document.body.setAttribute('data-theme', saved);
  dom.themeToggle.setAttribute('aria-pressed', String(saved === 'light'));
  dom.themeToggle.setAttribute('aria-label',
    saved === 'light' ? 'Basculer vers le mode sombre' : 'Basculer vers le mode clair'
  );
  dom.themeToggle.innerHTML = saved === 'light' ? ICONS.sun : ICONS.moon;
}

/* ============================================================
   4. INITIALISATION
   ============================================================ */

function initApp() {
  cacheElements();
  loadTheme();
  // Initialise l'icône du bouton œil
  dom.visToggle.innerHTML = ICONS.eye;
  attachListeners();
  // Vide l'interface au démarrage
  resetUI();
}

document.addEventListener('DOMContentLoaded', initApp);
