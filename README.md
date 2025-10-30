# LUCYBOX

**LUCYBOX** is a Python-based network security tool inspired by [EveBox](https://github.com/jasonish/evebox), designed to provide full-featured alert management and analysis for Suricata or other IDS systems. It combines real-time monitoring, intuitive visualization, and Python-native flexibility, making it easy for security analysts and developers to manage alerts efficiently.

---

## 🚀 Features

- **Real-time alert monitoring:** Track and manage IDS alerts as they occur.
- **Search, filter, and sort:** Quickly find alerts by type, severity, source, or time.
- **Web-based interface:** User-friendly dashboard for visualizing alerts.
- **Suricata EVE JSON support:** Fully compatible with Suricata's logging format.
- **Python-native implementation:** Easy to customize and extend.
- **Lightweight deployment:** Minimal dependencies for quick setup.

---

## 🛠️ Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/your-username/LUCYBOX.git
cd LUCYBOX
pip install -r requirements.txt

⚡ Usage

Run the tool:
python app.py

Open the web interface in your browser:
http://localhost:8080

📊 Configuration

Configuration options are stored in config.yaml:
port: 8080
log_path: /path/to/eve.json
refresh_interval: 5  # seconds


💡 Contribution

Contributions are welcome! Whether it’s a bug fix, new feature, or enhancement:

Fork the repository

Create a feature branch (git checkout -b feature-name)

Commit your changes (git commit -m "Add new feature")

Push to the branch (git push origin feature-name)

Open a Pull Request
