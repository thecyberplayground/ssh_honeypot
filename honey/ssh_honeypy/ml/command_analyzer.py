"""
Command analyzer for SSH honeypot.
Classifies commands by intent using a simple ML model.
"""
import pandas as pd
import numpy as np
import os
import pickle
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from pathlib import Path
from .config import DEFAULT_MODEL_PATH, MODEL_DIR


class CommandClassifier:
    """
    A simple ML classifier that categorizes SSH commands by their intent.
    Categories include: reconnaissance, persistence, privilege_escalation, 
    lateral_movement, data_exfiltration, and miscellaneous.
    """
    
    def __init__(self, model_path=None):
        """
        Initialize the classifier, optionally loading a pre-trained model.
        """
        self.categories = [
            'reconnaissance', 'persistence', 'privilege_escalation',
            'lateral_movement', 'data_exfiltration', 'miscellaneous'
        ]
        
        # Define commands for each category for initial training
        self.category_examples = {
            'reconnaissance': ['ls', 'pwd', 'whoami', 'id', 'uname', 'ps', 'netstat', 'ifconfig', 'cat /etc/passwd', 
                               'ls -la', 'ls -l', 'find', 'w', 'who', 'last', 'finger', 'arp -a', 'cat /etc/resolv.conf'],
            'persistence': ['crontab', 'at', 'ssh-keygen', 'useradd', 'chmod +x', 'nohup', 
                           'touch /var/spool/cron', 'echo "* * * * *"', 'chmod 644 .ssh/authorized_keys'],
            'privilege_escalation': ['sudo', 'su', 'chmod u+s', 'find / -perm -4000', 'chmod 4755', 'pkexec',
                                    'sudo -l', 'sudo -i', 'su -', 'perl -e', 'python -c', 'gcc exploit.c'],
            'lateral_movement': ['ssh', 'scp', 'nc', 'rsync', 'ssh-copy-id', 'sftp',
                                'ssh-keyscan', 'ssh-agent', 'telnet', 'rlogin'],
            'data_exfiltration': ['tar', 'zip', 'curl -O', 'wget', 'scp', 'base64', 'gzip', 'bzip2',
                                 'dd if=', 'cat file | nc', 'rm -rf', 'shred', 'sftp'],
            'miscellaneous': ['echo', 'cd', 'touch', 'mkdir', 'rm', 'grep', 'clear', 'cat', 'more',
                             'less', 'head', 'tail', 'mv', 'cp', 'man', 'info', 'vi', 'nano']
        }
        
        # Create a Pipeline with CountVectorizer and MultinomialNB
        self.pipeline = Pipeline([
            ('vectorizer', CountVectorizer(analyzer='char', ngram_range=(1, 3))),
            ('classifier', MultinomialNB())
        ])
        
        # Default path to save/load models if none specified
        if model_path is None:
            model_path = DEFAULT_MODEL_PATH
        
        # Directory check
        Path(MODEL_DIR).mkdir(exist_ok=True, parents=True)
        
        # Load or train model
        if os.path.exists(model_path):
            self.load_model(model_path)
        else:
            self._train_initial_model()
            # Save the new model
            self.save_model(model_path)
    
    def _train_initial_model(self):
        """
        Train an initial model using the predefined examples.
        """
        X = []
        y = []
        
        # Create training data from examples
        for category, commands in self.category_examples.items():
            for cmd in commands:
                X.append(cmd)
                y.append(category)
        
        # Fit the pipeline on the initial data
        self.pipeline.fit(X, y)
    
    def predict(self, command):
        """
        Predict the intent category of a command.
        
        Args:
            command (str): SSH command to classify
            
        Returns:
            dict: Category prediction and confidence score
        """
        # Get the prediction and probability
        category = self.pipeline.predict([command])[0]
        probabilities = self.pipeline.predict_proba([command])[0]
        confidence = max(probabilities)
        
        return {
            'command': command,
            'category': category,
            'confidence': confidence,
            'all_probabilities': dict(zip(self.pipeline.classes_, probabilities))
        }
    
    def batch_predict(self, commands):
        """
        Classify multiple commands at once.
        
        Args:
            commands (list): List of SSH commands
            
        Returns:
            list: List of prediction dictionaries
        """
        return [self.predict(cmd) for cmd in commands]
    
    def train(self, commands, categories):
        """
        Update the model with new training data.
        
        Args:
            commands (list): List of command strings
            categories (list): Corresponding categories
        """
        # Update with new data
        self.pipeline.fit(commands, categories)
    
    def save_model(self, path):
        """
        Save the trained model to disk.
        
        Args:
            path (str): Path to save the model
        """
        with open(path, 'wb') as f:
            pickle.dump(self.pipeline, f)
    
    def load_model(self, path):
        """
        Load a trained model from disk.
        
        Args:
            path (str): Path to the saved model
        """
        try:
            with open(path, 'rb') as f:
                self.pipeline = pickle.load(f)
        except Exception as e:
            print(f"Error loading model from {path}: {e}")
            self._train_initial_model()
            
    def get_insights(self, commands):
        """
        Generate insights based on a set of commands.
        
        Args:
            commands (list): List of commands to analyze
            
        Returns:
            dict: Statistics and insights about command patterns
        """
        if not commands:
            return {"status": "No commands found"}
            
        predictions = self.batch_predict(commands)
        categories = [p['category'] for p in predictions]
        
        # Aggregate stats
        category_counts = pd.Series(categories).value_counts().to_dict()
        
        # Calculate percentages
        total = len(categories)
        category_percentages = {k: (v / total) * 100 for k, v in category_counts.items()}
        
        # Find most common commands by category
        commands_by_category = {}
        for pred in predictions:
            cat = pred['category']
            cmd = pred['command']
            if cat not in commands_by_category:
                commands_by_category[cat] = []
            commands_by_category[cat].append(cmd)
        
        top_commands = {}
        for cat, cmds in commands_by_category.items():
            series = pd.Series(cmds)
            top_commands[cat] = series.value_counts().head(5).to_dict()
        
        return {
            'total_commands': total,
            'category_counts': category_counts,
            'category_percentages': category_percentages,
            'top_commands_by_category': top_commands,
            'attack_focus': max(category_percentages.items(), key=lambda x: x[1])[0]
        }
