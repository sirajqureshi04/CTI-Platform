import json
import os

class FeedState:
    def __init__(self, feed_name: str):
        self.state_dir = "backend/cache/state/feeds"
        self.state_file = os.path.join(self.state_dir, f"{feed_name}.json")
        os.makedirs(self.state_dir, exist_ok=True)
        self.data = self._load()

    def _load(self):
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return {}
        return {}

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value):
        self.data[key] = value
        with open(self.state_file, 'w') as f:
            json.dump(self.data, f, indent=2)