
import toml, os
CONFIG = {}
def load_config(path="config.toml"):
    global CONFIG
    if os.path.exists(path):
        CONFIG = toml.load(path)
    else:
        CONFIG = {"server":{"host":"127.0.0.1","port":5000,"debug":True},"storage":{"db_path":"events.db","retention_days":30},"admin":{"token":"changeme"}}
    return CONFIG
