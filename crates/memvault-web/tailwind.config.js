/** @type {import('tailwindcss').Config} */
const tokenColor = (v) => `rgb(var(--${v}) / <alpha-value>)`;

module.exports = {
  darkMode: 'selector',
  content: ["./src/**/*.rs", "../../../plan-ai-design/src/**/*.rs"],
  safelist: ['td', 'th'],
  theme: {
    extend: {
      colors: {
        bg: tokenColor('c-bg'),
        brand: {
          DEFAULT: tokenColor('c-brand'),
          strong:  tokenColor('c-brand-strong'),
          soft:    tokenColor('c-brand-soft'),
        },
        surface: {
          DEFAULT: tokenColor('c-surface'),
          '2':     tokenColor('c-surface-2'),
          '3':     tokenColor('c-surface-3'),
          strong:  tokenColor('c-surface-strong'),
        },
        fg: {
          DEFAULT: tokenColor('c-fg'),
          strong:  tokenColor('c-fg-strong'),
          muted:   tokenColor('c-fg-muted'),
          faint:   tokenColor('c-fg-faint'),
          invert:  tokenColor('c-fg-invert'),
        },
        line: {
          DEFAULT: tokenColor('c-line'),
          soft:    tokenColor('c-line-soft'),
        },
        danger: {
          DEFAULT: tokenColor('c-danger'),
          strong:  tokenColor('c-danger-strong'),
          soft:    tokenColor('c-danger-soft'),
        },
        warn: {
          DEFAULT: tokenColor('c-warn'),
          strong:  tokenColor('c-warn-strong'),
          soft:    tokenColor('c-warn-soft'),
        },
        success: {
          DEFAULT: tokenColor('c-success'),
          soft:    tokenColor('c-success-soft'),
        },
        info: {
          DEFAULT: tokenColor('c-info'),
          soft:    tokenColor('c-info-soft'),
        },
        accent: {
          DEFAULT: tokenColor('c-accent'),
          strong:  tokenColor('c-accent-strong'),
          soft:    tokenColor('c-accent-soft'),
        },
      },
      boxShadow: {
        card: 'var(--shadow-card)',
      },
    },
  },
  plugins: [require("@tailwindcss/typography")],
};
