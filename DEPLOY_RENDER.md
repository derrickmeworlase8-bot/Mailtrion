# Deploying Snarelytics to Render

This replaces "build a standalone .exe and hand people the folder" with:
push to GitHub → connect the repo on Render → get one link anyone can open.

## What changed in the code to make this work

- `backend/app.py` now binds to `0.0.0.0` and reads the port from the
  `PORT` environment variable when it detects it's running hosted
  (Render sets `PORT` automatically). Locally, nothing changes — it
  still binds to `127.0.0.1:5000` as before.
- `app.secret_key` now reads from `FLASK_SECRET_KEY` if set, falling
  back to the old hardcoded value for local use. `render.yaml`
  auto-generates a random one for the hosted deployment.
- `frontend/index.html` now points API calls at `window.location.origin`
  instead of a hardcoded `http://127.0.0.1:5000`, so the same file works
  whether it's opened locally or served from your Render URL.
- Added `render.yaml`, `Procfile`, and this guide.

Nothing about `start.bat`, the PyInstaller build, or the Electron app was
touched — those still work exactly as before if you still want them.

## 1. Push the project to GitHub

```bash
cd phishguard-ai
git init
git add .
git commit -m "Prepare for Render deployment"
```

Create a new (empty) repo on GitHub, then:

```bash
git remote add origin https://github.com/<your-username>/phishguard-ai.git
git branch -M main
git push -u origin main
```

Check `.gitignore` first — it already excludes `phishguard.db`,
`client_secret.json`/`outlook_secret.json`, and `nltk_data/`, which is
correct: those are either per-deployment secrets or generated at build
time, not source.

## 2. Create the Render service

1. Go to https://dashboard.render.com → **New** → **Blueprint**.
2. Connect your GitHub account and select the `phishguard-ai` repo.
   Render will read `render.yaml` and pre-fill everything (build
   command, start command, a generated `FLASK_SECRET_KEY`).
3. Click **Apply**. First build takes a few minutes (installs
   scikit-learn, downloads NLTK data, etc.).

   If you'd rather set it up by hand instead of using the blueprint:
   **New → Web Service**, pick the repo, and set:
   - Build command: `pip install -r backend/requirements.txt && python backend/predownload_nltk.py`
   - Start command: `python backend/app.py`
   - Add an environment variable `FLASK_SECRET_KEY` with any random
     string value.

4. Once it deploys, Render gives you a URL like
   `https://phishguard-ai.onrender.com` — that's the link you share.
   No download, no per-machine setup, no `.exe` errors.

## 3. Important limitations on Render's free tier

- **The filesystem is ephemeral.** Every time you push a new commit
  (or the free-tier service spins down from inactivity and restarts),
  `phishguard.db` and anything in `uploads/`/`reports/` gets wiped and
  `phishguard.db` is recreated empty (the app auto-creates its tables
  on startup, so it won't error — but all users/scans from before the
  redeploy are gone). `models/model.pkl` and `models/vec.pkl` are
  fine since they're committed to the repo, not generated at runtime.
  If you need data to persist across deploys, upgrade to a paid plan
  with a persistent disk, or point `DB_PATH` at an external database.
- **Free services spin down after ~15 minutes of inactivity** and take
  10–30 seconds to wake back up on the next request. Fine for a class
  demo; mention it to whoever's grading so a slow first load isn't
  mistaken for a bug.
- **Gmail/Outlook OAuth won't work out of the box.** Those need a
  `client_secret.json`/`outlook_secret.json` (per `SETUP_GMAIL.md` /
  `SETUP_OUTLOOK.md`) and the redirect URI registered with
  Google/Microsoft has to match your live Render URL, not
  `localhost`. Manual `.eml` upload and IMAP (Yahoo, etc.) work
  without any of that.
