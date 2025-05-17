"""
Integration module for honeypot ML capabilities.
Connects the ML analysis tools with the honeypot system.
"""
from pathlib import Path
import pandas as pd
import threading
import time
import json
import os
import re
from .command_analyzer import CommandClassifier
from .config import (
    DEFAULT_MODEL_PATH, ANALYTICS_DIR, 
    ANALYSIS_INTERVAL, MIN_COMMANDS_FOR_ANALYSIS,
    MAX_STORED_INSIGHTS
)


class HoneypotMLAnalyzer:
    """
    Integrates machine learning capabilities with the honeypot.
    Runs periodic analysis to provide insights about attacks.
    """
    
    def __init__(self, log_path, model_path=None):
        """
        Initialize the analyzer.
        
        Args:
            log_path (str): Path to the command log file
            model_path (str, optional): Path to a pre-trained model
        """
        self.log_path = Path(log_path)
        
        # Initialize ML components
        if model_path:
            self.classifier = CommandClassifier(model_path)
        else:
            self.classifier = CommandClassifier(DEFAULT_MODEL_PATH)
        
        # Analysis results
        self.insights = {}
        self.last_analysis_time = 0
        
        # Analytics output directory
        self.output_dir = Path(ANALYTICS_DIR)
        self.output_dir.mkdir(exist_ok=True, parents=True)
    
    def parse_command_log(self):
        """
        Parse the command log file to extract commands.
        
        Returns:
            list: Extracted commands
        """
        commands = []
        
        if not self.log_path.exists():
            return commands
            
        try:
            with open(self.log_path, 'r') as file:
                for line in file:
                    line = line.strip()
                    if "Command b'" in line:
                        # Extract command using the pattern from dashboard_data_parser.py
                        pattern = re.compile(r"Command b'([^']*)'executed by (\d+\.\d+\.\d+\.\d+)")
                        match = pattern.search(line)
                        if match:
                            command = match.groups()[0]
                            commands.append(command)
        except Exception as e:
            print(f"Error parsing command log: {e}")
        
        return commands
    
    def analyze_logs(self):
        """
        Analyze the command logs and generate insights.
        
        Returns:
            dict: Analysis insights
        """
        commands = self.parse_command_log()
        if not commands or len(commands) < MIN_COMMANDS_FOR_ANALYSIS:
            return {"status": f"Insufficient commands found ({len(commands)}). Need at least {MIN_COMMANDS_FOR_ANALYSIS}."}
        
        # Generate insights using the classifier
        self.insights = self.classifier.get_insights(commands)
        self.last_analysis_time = time.time()
        
        # Save insights to JSON
        timestamp = int(self.last_analysis_time)
        insights_path = self.output_dir / f'insights_{timestamp}.json'
        try:
            with open(insights_path, 'w') as f:
                json.dump(self.insights, f, indent=2)
            
            # Also save latest insights for easy access
            latest_path = self.output_dir / 'latest_insights.json'
            with open(latest_path, 'w') as f:
                json.dump(self.insights, f, indent=2)
                
            # Clean up old insight files
            self._cleanup_old_insights()
        except Exception as e:
            print(f"Error saving insights: {e}")
        
        return self.insights
    
    def _cleanup_old_insights(self):
        """
        Remove old insight files to prevent disk space issues.
        Keeps only the MAX_STORED_INSIGHTS most recent files.
        """
        try:
            insight_files = list(self.output_dir.glob('insights_*.json'))
            insight_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            
            # Keep only the most recent files
            if len(insight_files) > MAX_STORED_INSIGHTS:
                for old_file in insight_files[MAX_STORED_INSIGHTS:]:
                    old_file.unlink()
        except Exception as e:
            print(f"Error cleaning up old insights: {e}")
    
    def start_background_analysis(self, interval=None):
        """
        Start a background thread that periodically analyzes logs.
        
        Args:
            interval (int): Time between analyses in seconds, default from config
        """
        if interval is None:
            interval = ANALYSIS_INTERVAL
            
        def background_task():
            while True:
                try:
                    self.analyze_logs()
                except Exception as e:
                    print(f"Error in background analysis: {str(e)}")
                finally:
                    time.sleep(interval)
        
        thread = threading.Thread(target=background_task, daemon=True)
        thread.start()
        return thread
    
    def get_latest_insights(self):
        """
        Get the latest insights, either from memory or from saved file.
        
        Returns:
            dict: Latest insights or empty dict if none available
        """
        if self.insights:
            return self.insights
            
        latest_path = self.output_dir / 'latest_insights.json'
        if latest_path.exists():
            try:
                with open(latest_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading latest insights: {e}")
                
        return {}
