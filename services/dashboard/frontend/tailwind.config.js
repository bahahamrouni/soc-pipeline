/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        soc: {
          bg:       '#0a0e1a',
          panel:    '#111827',
          border:   '#1f2937',
          accent:   '#3b82f6',
          critical: '#ef4444',
          high:     '#f97316',
          medium:   '#eab308',
          low:      '#3b82f6',
          success:  '#22c55e',
          muted:    '#6b7280',
        }
      }
    }
  },
  plugins: []
}