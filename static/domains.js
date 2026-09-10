// Shared domain configuration — single source of truth for guest + admin UIs.
// To add a new HA entity domain, edit only this file.
const DOMAIN_ORDER = ['light','switch','input_boolean','climate','lock','button','input_button','media_player','cover','fan','sensor','binary_sensor'];
const DOMAIN_LABELS = {
  light: 'Lights', switch: 'Switches', input_boolean: 'Switches', climate: 'Climate',
  lock: 'Locks', button: 'Buttons', input_button: 'Buttons', media_player: 'Media', cover: 'Covers', fan: 'Fans',
  sensor: 'Sensors', binary_sensor: 'Binary Sensors',
};
const DOMAIN_LABELS_ES = {
  light: 'Luces', switch: 'Interruptores', input_boolean: 'Interruptores', climate: 'Climatización',
  lock: 'Cerraduras', button: 'Botones', input_button: 'Botones', media_player: 'Multimedia', cover: 'Toldos/Persianas', fan: 'Ventiladores',
  sensor: 'Sensores', binary_sensor: 'Sensores binarios',
};
// LANG is a global set by each page's own inline script (admin_dashboard.html /
// guest_pwa.html), always defined by the time this is actually called even
// though domains.js itself loads first — it's only read lazily, at call time.
function domainLabel(domain) {
  const table = (typeof LANG !== 'undefined' && LANG === 'es') ? DOMAIN_LABELS_ES : DOMAIN_LABELS;
  return table[domain];
}
const DOMAIN_ICONS = {
  light: 'lightbulb', switch: 'toggle_on', input_boolean: 'toggle_on', climate: 'thermostat',
  lock: 'lock', button: 'smart_button', input_button: 'smart_button', media_player: 'speaker', cover: 'blinds', fan: 'mode_fan',
  sensor: 'sensors', binary_sensor: 'motion_sensor_active',
};
// What an entity is *doing*, not what kind of thing it is, is what drives the
// colour of its icon shape — the single most recognisable trait of the
// Mushroom cards this design follows. An idle entity goes neutral, so a room
// full of switched-off lights reads as calm instead of as a wall of amber.
//
// Deliberately separate from the brand colours an admin configures
// (BRAND_PRIMARY/BRAND_BG): those drive the interactive chrome — buttons,
// toggles, focus rings — while these say what the house is doing. Tying the
// two together would mean a red-brand install showing "cool" in red.
const NEUTRAL_COLOR = { bg: 'bg-soot/[0.07] dark:bg-white/10', text: 'text-muted' };

const STATE_COLORS = {
  green: { bg: 'bg-emerald-500/15', text: 'text-emerald-600 dark:text-emerald-400' },
  red: { bg: 'bg-red-500/15', text: 'text-red-500 dark:text-red-400' },
  amber: { bg: 'bg-amber-500/15', text: 'text-amber-500' },
  blue: { bg: 'bg-blue-500/15', text: 'text-blue-500 dark:text-blue-400' },
  sky: { bg: 'bg-sky-500/15', text: 'text-sky-500 dark:text-sky-400' },
  purple: { bg: 'bg-purple-500/15', text: 'text-purple-500 dark:text-purple-400' },
  teal: { bg: 'bg-teal-600/15', text: 'text-teal-600 dark:text-teal-400' },
};

function entityColor(domain, stateStr, state) {
  const s = stateStr || 'unknown';
  if (s === 'unavailable' || s === 'unknown') return NEUTRAL_COLOR;

  switch (domain) {
    // A lock is the one entity here whose colours carry a real warning, so it
    // stays coloured either way rather than going neutral when secured.
    case 'lock':
      return s === 'locked' ? STATE_COLORS.green : STATE_COLORS.red;
    // Stateless triggers: their "state" is a last-pressed timestamp, so there
    // is no idle to grey out.
    case 'button':
    case 'input_button':
      return STATE_COLORS.red;
    case 'cover':
      return s === 'closed' ? NEUTRAL_COLOR : STATE_COLORS.sky;
    case 'climate': {
      if (s === 'off') return NEUTRAL_COLOR;
      const action = state?.attributes?.hvac_action || s;
      if (action === 'heating' || action === 'heat') return STATE_COLORS.red;
      return STATE_COLORS.blue;
    }
    case 'media_player':
      return s === 'off' || s === 'idle' || s === 'standby'
        ? NEUTRAL_COLOR : STATE_COLORS.purple;
    case 'light':
      return s === 'on' ? STATE_COLORS.amber : NEUTRAL_COLOR;
    case 'fan':
      return s === 'on' ? STATE_COLORS.teal : NEUTRAL_COLOR;
    case 'switch':
    case 'input_boolean':
      return s === 'on' ? STATE_COLORS.teal : NEUTRAL_COLOR;
    case 'binary_sensor':
      return s === 'on' ? STATE_COLORS.amber : NEUTRAL_COLOR;
    default:
      return s === 'on' ? STATE_COLORS.amber : NEUTRAL_COLOR;
  }
}

const DOMAIN_COLORS = {
  light: { bg: 'bg-amber-500/10', text: 'text-amber-500', icon: 'bg-amber-500' },
  switch: { bg: 'bg-teal-600/10', text: 'text-teal-600', icon: 'bg-teal-600' },
  input_boolean: { bg: 'bg-teal-600/10', text: 'text-teal-600', icon: 'bg-teal-600' },
  climate: { bg: 'bg-blue-500/10', text: 'text-blue-500', icon: 'bg-blue-500' },
  lock: { bg: 'bg-red-500/10', text: 'text-red-500', icon: 'bg-red-500' },
  button: { bg: 'bg-red-500/10', text: 'text-red-500', icon: 'bg-red-500' },
  input_button: { bg: 'bg-red-500/10', text: 'text-red-500', icon: 'bg-red-500' },
  media_player: { bg: 'bg-purple-500/10', text: 'text-purple-500', icon: 'bg-purple-500' },
  cover: { bg: 'bg-sky-500/10', text: 'text-sky-500', icon: 'bg-sky-500' },
  fan: { bg: 'bg-emerald-500/10', text: 'text-emerald-500', icon: 'bg-emerald-500' },
  sensor: { bg: 'bg-cyan-500/10', text: 'text-cyan-600', icon: 'bg-cyan-600' },
  binary_sensor: { bg: 'bg-lime-500/10', text: 'text-lime-600', icon: 'bg-lime-600' },
};
