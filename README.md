# CyberGuard
Developed a full-stack cybersecurity detection system that integrates deep learning models (LSTM &amp; BILSTM) with a web-based simulation platform to identify and mitigate web-based cyber threats.
# 🛡️ CyberGuard: Deep Learning Cyberattack Detection System

CyberGuard is an AI-powered cybersecurity detection system designed to identify and mitigate three of the most critical web-based attacks: **SQL Injection (SQLi)**, **Cross-Site Scripting (XSS)**, and **Phishing URLs**. It integrates advanced deep learning models with a responsive Flask web interface for real-time threat detection, alerting, and mitigation.

---

## 🚀 Project Highlights

- 🔍 Detects **SQLi**, **XSS**, and **Phishing** attacks using LSTM and BiLSTM architectures.
- 💻 Real-time web interface with IP blocking and admin alert system.
- 📈 Achieved over **97% accuracy** across all models.
- 🌐 Flask-based web simulation with full frontend/backend integration.

---

## 📁 Project Structure
CyberGuard/
├── app.py # Flask application
├── model/
│ ├── sql_lstm_model.h5
│ ├── xss_bilstm_model.h5
│ └── phishing_model.h5
├── utils/
│ └── preprocessing.py
├── templates/
│ ├── index.html
│ └── admin.html
├── static/
│ ├── style.css
│ └── script.js
├── requirements.txt
└── README.md

---

## 🧠 Models Used

| Attack Type    | Model       | Accuracy | Precision | Recall | F1-Score | AUC-ROC |
|----------------|-------------|----------|-----------|--------|----------|---------|
| SQL Injection  | LSTM        | 97.7%    | 98.1%     | 97.3%  | 97.7%    | 0.98    |
| XSS            | BiLSTM      | 98.3%    | 98.6%     | 98.0%  | 98.3%    | 0.99    |
| Phishing URLs  | LSTM        | 96.9%    | 97.0%     | 96.7%  | 96.8%    | 0.97    |

---

## 🛠️ Technologies Used

- **Backend**: Flask, Python
- **Frontend**: HTML, CSS, JavaScript, Bootstrap
- **Deep Learning**: TensorFlow/Keras (LSTM, BiLSTM)
- **Security**: bcrypt, re (regex), IP tracking
- **Development Tools**: Google Colab (T4, A100), VS Code

---

## 🧪 Datasets

- **SQL Injection**: 148,000 labeled SQL queries (benign vs. malicious)
- **XSS**: HTML/JavaScript scripts and plain text samples
- **Phishing**: 90,000+ URLs (legitimate and phishing)

Each dataset is balanced and preprocessed with character-level tokenization, cleaning, and padding.

---

## 🧬 Model Pipeline

1. Data Cleaning & Normalization
2. Character-level Tokenization
3. Padding based on 95th percentile length
4. Train/Test Split (80/20)
5. Model Training (LSTM / BiLSTM)
6. Evaluation (Precision, Recall, F1, AUC)
7. Integration into Flask Web App

---

## 🖥️ Live Web Simulation Features

- ✅ User login and registration interface
- 🚫 IP blocking system for repeated attacks
- ⚠️ Admin dashboard with real-time alerts
- 📄 Logging system (attacks, IPs, timestamps)
- 🔗 Phishing detection in posted ads or links

---

## 🧠 How to Run Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Run the Flask app
python app.py
