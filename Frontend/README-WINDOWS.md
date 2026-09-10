# SentinelStream Local Prototype

A self-contained React/Vite recreation of the SentinelStream security observability dashboard prototype.

## What is included

- Dark SOC-style dashboard with overview metrics, event velocity chart, open incidents, alert sources, and Kafka pipeline status.
- Responsive layout for desktop, tablet, and mobile screens.
- Interactive sidebar navigation for Overview, Live Logs, Alerts, Threat Map, Prediction, Injection Lab, and Documentation.
- Prototype interactions for stream actions, incident rows, search, settings, and workspace cards.
- No database, API keys, environment variables, or external services are required.

## Run on Windows

### Option A — one-click script

1. Install **Node.js LTS** from <https://nodejs.org/> if it is not already installed.
2. Extract the `sentinelstream-local.zip` archive to a folder you can access.
3. Double-click `run-local.bat`.
4. When the terminal says the server is ready, open <http://localhost:3000/> in your browser.
5. Keep the terminal window open while using the site. Press `Ctrl+C` in that window to stop the server.

The script installs dependencies the first time it runs and starts the Vite development server on subsequent runs.

### Option B — PowerShell / Command Prompt

Open a terminal in the extracted project folder and run:

```powershell
npm install
npm run dev
```

Then open <http://localhost:3000/>.

If you prefer pnpm, you can use:

```powershell
corepack enable
pnpm install
pnpm dev
```

## Production build

To create an optimized build:

```powershell
npm run build
```

To serve the production build locally:

```powershell
npm run start
```

The production server uses port `3000` by default. To use another port in PowerShell:

```powershell
$env:PORT=4173; npm run start
```

## Project structure

```text
client/
  index.html
  src/
    App.tsx
    index.css
    main.tsx
    pages/Home.tsx
server/index.ts
shared/const.ts
package.json
pnpm-lock.yaml
run-local.bat
README-WINDOWS.md
```

This is a frontend prototype. The metrics and incidents are demo data generated in the browser; they are not connected to a real Kafka cluster or security data source.

## Editing the prototype

- Main UI and interactions: `client/src/pages/Home.tsx`
- Visual system and responsive CSS: `client/src/index.css`
- Browser metadata: `client/index.html`
- Start script configuration: `package.json`

A current Node.js LTS release (18+ recommended) is sufficient.
