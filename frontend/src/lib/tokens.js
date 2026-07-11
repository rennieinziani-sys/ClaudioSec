export const colors = {
  bg:      '#141414',
  bg2:     '#1a1a1a',
  bg3:     '#202020',
  bg4:     '#272727',
  border:  '#2a2a2a',
  border2: '#333',
  text:    '#d4d4d4',
  muted:   '#555',
  dim:     '#3a3a3a',

  green:   '#3ddc84',
  greenDim:'#1a4a35',
  greenGlow:'rgba(61,220,132,0.12)',

  red:     '#e05555',
  redDim:  '#4a1f1f',
  redGlow: 'rgba(224,85,85,0.12)',

  orange:  '#dd8844',
  oraDim:  '#4a2e14',
  oraGlow: 'rgba(221,136,68,0.10)',

  yellow:  '#c9b44a',
  yelDim:  '#3d3214',
  yelGlow: 'rgba(201,180,74,0.08)',

  cyan:    '#3db8dd',
  cyanGlow:'rgba(61,184,221,0.10)',
};

export const font = {
  mono: "'Share Tech Mono', monospace",
  body: "'Space Grotesk', sans-serif",
  display: "'Orbitron', sans-serif",
};

export const SEV_COLOR = {
  critical: colors.red,
  high:     colors.orange,
  medium:   colors.yellow,
  low:      colors.green,
};

export const SEV_BG = {
  critical: colors.redGlow,
  high:     colors.oraGlow,
  medium:   colors.yelGlow,
  low:      colors.greenGlow,
};

export const SEV_BORDER = {
  critical: 'rgba(224,85,85,0.3)',
  high:     'rgba(221,136,68,0.3)',
  medium:   'rgba(201,180,74,0.25)',
  low:      'rgba(61,220,132,0.2)',
};