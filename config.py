# config.py

import os
from dotenv import load_dotenv

load_dotenv()  # Load variables from .env file

HF_TOKEN = os.getenv("HF_TOKEN")
