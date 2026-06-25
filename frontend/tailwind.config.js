/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: ['class'],
  theme: {
    extend: {
      colors: {
        trident: {
          bg: 'rgb(var(--color-trident-bg) / <alpha-value>)',
          surface: 'rgb(var(--color-trident-surface) / <alpha-value>)',
          border: 'rgb(var(--color-trident-border) / <alpha-value>)',
          'border-hover': 'rgb(var(--color-trident-border-hover) / <alpha-value>)',
          accent: 'rgb(var(--color-trident-accent) / <alpha-value>)',
          'accent-hover': 'rgb(var(--color-trident-accent-hover) / <alpha-value>)',
          success: 'rgb(var(--color-trident-success) / <alpha-value>)',
          warning: 'rgb(var(--color-trident-warning) / <alpha-value>)',
          danger: 'rgb(var(--color-trident-danger) / <alpha-value>)',
          muted: 'rgb(var(--color-trident-muted) / <alpha-value>)',
          text: 'rgb(var(--color-trident-text) / <alpha-value>)',
          'text-secondary': 'rgb(var(--color-trident-text) / <alpha-value>)',
          'border-subtle': 'rgb(var(--color-trident-border-subtle) / <alpha-value>)',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        heading: ['Montserrat', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
};
