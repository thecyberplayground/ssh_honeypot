"""
Configuration settings for machine learning components.
"""
from pathlib import Path
import os

# Get base directory
BASE_DIR = Path(__file__).parent.parent

# Analysis settings
ANALYSIS_INTERVAL = 3600  # How often to run analysis (in seconds)
MIN_COMMANDS_FOR_ANALYSIS = 10  # Minimum number of commands needed for meaningful analysis

# Model settings
MODEL_DIR = os.path.join(BASE_DIR, "ml", "models")
DEFAULT_MODEL = "command_classifier.pkl"
DEFAULT_MODEL_PATH = os.path.join(MODEL_DIR, DEFAULT_MODEL)

# Analytics settings
ANALYTICS_DIR = os.path.join(BASE_DIR, "ml", "analytics")
MAX_STORED_INSIGHTS = 20  # Maximum number of insight files to keep
