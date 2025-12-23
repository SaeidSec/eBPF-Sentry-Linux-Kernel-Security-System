# eBPF-Sentry: Complete User Guide

This guide covers everything from starting the dashboard to testing advanced protection modes.

## 🏁 Phase 1: Start the Dashboard
You need the dashboard running to visualize alerts.

### Start Backend (Terminal 1)
```bash
cd /home/bear/Desktop/Raqhive/dashboard/server
python3 app.py
```
*Keep this terminal open.*

### Start Frontend (Terminal 2)
```bash
cd /home/bear/Desktop/Raqhive/dashboard/client
npm run dev
```
*Keep this terminal open.*
👉 **Open in Browser:** [http://localhost:5173](http://localhost:5173)

## 🛡️ Phase 2: Run the Security Tool
This is the core eBPF agent that monitors the kernel.

### Start Sentry Agent (Terminal 3 - Root Required)
```bash
cd /home/bear/Desktop/Raqhive
sudo python3 src/sentry_core.py
```
You will see a menu:
1. **Monitor Mode (IDS):** Logs events but allows them.
2. **Active Defense Mode (IDS + IPS):** Logs events AND kills malicious processes.

## 🧪 Phase 3: Testing & Verification

### Scenario A: Testing Monitor Mode (Option 1)
**Goal:** See an alert without blocking the process.

1. Select **Option 1** in the Sentry Agent (Terminal 3).
2. Open a new terminal (Terminal 4) and run:
   ```bash
   cat /etc/shadow
   ```
   *(This mimics a sensitive file access)*
3. **Verify:**
   - The command will succeed (permission denied usually, but not killed by Sentry).
   - Sentry will log `[ALERT] Sensitive File Access`.

### Scenario B: Testing Active Defense (Option 2)
**Goal:** Verify that a malicious process is instantly killed.

1. Restart Sentry Agent in Terminal 3 and select **Option 2**.
2. Run the Test Malware in Terminal 4:
   ```bash
   /tmp/malware_test
   ```
3. **Verify:**
   - You see `Killed` or `Terminated` immediately.
   - The script does **NOT** run.
   - Sentry logs `[IPS BLOCK] ... KILLED`.

## 📊 Phase 4: Vizualize on Dashboard
After running tests, send the logs to your dashboard.

### Ship Logs (Terminal 4)
```bash
cd /home/bear/Desktop/Raqhive
python3 src/log_shipper.py
```
*   **Username:** admin
*   **Password:** password (or anything else)

### Check Dashboard:
1. Refresh [http://localhost:5173](http://localhost:5173).
2. You will see the new events.
3. Click on a row to see full details (Rule, Process, Timestamp).
