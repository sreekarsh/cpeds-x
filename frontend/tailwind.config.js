/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#0a0e1a',
          panel: '#121826',
          border: '#1f2937',
          accent: '#22d3ee',
        }
      }
    },
  },
  plugins: [],
}
