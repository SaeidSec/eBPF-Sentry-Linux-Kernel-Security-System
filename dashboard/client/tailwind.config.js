/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        dark: {
          900: '#1a1b26',
          800: '#24283b',
          700: '#414868',
        },
        primary: '#7aa2f7',
        accent: '#bb9af7',
        danger: '#f7768e',
        success: '#9ece6a',
        warning: '#e0af68',
      }
    },
  },
  plugins: [],
}
