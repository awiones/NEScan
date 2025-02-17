import random
import pathlib
from typing import Optional

class UserAgentManager:
    def __init__(self, user_agents_file: str = "user_agents.txt"):
        self.user_agents_file = pathlib.Path(user_agents_file)
        self.user_agents = self._load_user_agents()
        
    def _load_user_agents(self) -> list:
        """Load user agents from file"""
        try:
            with open(self.user_agents_file, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            return [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ]

    def get_random_agent(self) -> str:
        """Return a random user agent string"""
        return random.choice(self.user_agents)

    def rotate_user_agent(self, current_agent: Optional[str] = None) -> str:
        """Rotate to a new user agent, different from the current one"""
        if not current_agent or current_agent not in self.user_agents:
            return self.get_random_agent()
            
        available_agents = [ua for ua in self.user_agents if ua != current_agent]
        return random.choice(available_agents) if available_agents else current_agent
