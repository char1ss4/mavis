import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // Localhost only: the page shows watchlist matches
    host: '127.0.0.1',
    // In development, forward API calls to `python cli.py serve`
    proxy: { '/api': 'http://127.0.0.1:8000' },
  },
})
