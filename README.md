# ITRI625 Project - Intrusion Detection (MLP) + Desktop App

## Structure

```
notebooks/IDS_Deep_Learning_Model.ipynb   Model development, training, evaluation, XAI (rubric 2.1-2.4, 2.6-2.7, theory)
api/api.py                                FastAPI service that serves the trained model (rubric 2.5)
desktop_app/desktop_app.py                Tkinter GUI client for the API (rubric 2.5)
models/                                   Saved model + preprocessor + metrics (created by the notebook)
requirements.txt                          Everything needed to run all three pieces
```

## 1. Train the model

1. Install dependencies: `pip install -r requirements.txt`
2. Download the dataset from Kaggle (see the notebook's intro cell) and place
   the CSV where `DATA_PATH` in the notebook points, or update that path.
3. Run `notebooks/IDS_Deep_Learning_Model.ipynb` top to bottom. This trains
   the MLP, logs metrics, plots the required graphs, and - in the final
   cell - saves everything the API needs into `models/`.

## 2. Start the API

```bash
cd api
uvicorn api:app --reload --port 8000
```

Visit `http://127.0.0.1:8000/docs` for interactive Swagger docs. Endpoints:

- `GET  /health`  - liveness check + whether the model artefacts loaded
- `GET  /metrics` - the test-set accuracy/precision/recall/F1/AUC-ROC from the notebook
- `POST /predict` - classify one session as Normal/Attack, given its raw features

## 3. Start the desktop app

```bash
cd desktop_app
python desktop_app.py
```

The app:

- Lets you type in a session's raw features (or load one of two built-in
  sample sessions) through dropdowns/entry boxes matched to the dataset's
  actual categories (protocol, encryption, browser).
- Sends them to `POST /predict` on a background thread (the window never
  freezes) and shows **Normal**/**Attack** with the predicted probability,
  color-coded green/red.
- Has a "View model performance" button that pulls `/metrics` and shows the
  test-set scores, so a user doesn't need to open the notebook to see how
  trustworthy the model is.
- Shows a live API-connection status line, and gives clear error dialogs
  if the API is unreachable, the model hasn't been trained yet, or a field
  is filled in incorrectly - rather than crashing.

## Rubric coverage (practical, 70 marks)

| Item | Where |
|---|---|
| 2.1 Model development | `notebooks/...ipynb`, Sections 4-5 |
| 2.2 Train/val/test split | Section 3 (stratified 60/20/20) |
| 2.3 Evaluation metric logging | Sections 5-6, exposed live via `/metrics` |
| 2.4 Metric graphs | Section 7 (ROC, PR curve, confusion matrix, loss/accuracy curves) |
| 2.5 Desktop application | `api/api.py` (FastAPI) + `desktop_app/desktop_app.py` (Tkinter) |
| 2.6 Patience / early stopping | Section 5 (`EarlyStopping(patience=8, restore_best_weights=True)`) |
| 2.7 Additional features | Section 8 (SHAP explainability, bonus) |

Remember the two deductions: keep all notebook outputs visible (don't clear
them before submitting) and commit regularly to GitHub throughout, not just
at the end.
