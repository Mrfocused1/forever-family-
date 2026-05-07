/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./*.html'],
  theme: {
    extend: {
      colors: {
        gold:  '#D4AF37',
        stone: '#2A2A2A',
      },
      fontFamily: {
        condensed: ['Oswald', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
