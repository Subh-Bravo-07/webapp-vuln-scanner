import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'Segoe UI', 'Roboto', 'Arial', 'Noto Sans', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'Liberation Mono', 'Courier New', 'monospace'],
      },
      colors: {
        hs: {
          bg0: '#070A14',
          bg1: '#0B1020',
          panel: '#141B34',
          border: 'rgba(148,163,184,.18)',
          text: '#E5E7EB',
          muted: '#A7B0C0',
          accA: '#22D3EE',
          accB: '#A78BFA',
          danger: '#FB7185',
          warn: '#FBBF24',
          ok: '#34D399',
        },
      },
      boxShadow: {
        hs: '0 18px 45px rgba(0,0,0,.45)',
      },
      borderRadius: {
        hs: '16px',
      },
    },
  },
  plugins: [],
} satisfies Config

