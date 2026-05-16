import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{vue,ts}'],
  theme: {
    extend: {
      colors: {
        surface: {
          950: '#070b12',
          900: '#0b111c',
          850: '#101826',
          800: '#142033',
          700: '#1c2a3f',
        },
        signal: {
          cyan: '#38bdf8',
          green: '#22c55e',
          amber: '#f59e0b',
          red: '#ef4444',
        },
      },
      boxShadow: {
        panel: '0 18px 50px rgba(0, 0, 0, 0.28)',
      },
    },
  },
  plugins: [],
} satisfies Config
