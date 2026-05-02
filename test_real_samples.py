#!/usr/bin/env python3
"""
Test Scanner on Real Malware and Benign Files
Uses actual files from malware/ and safeware/ directories
"""

import os
import sys
import json
from pathlib import Path
from standalone_scanner import LocalMalwareScanner, YARA_RULES_PATH, CUSTOM_SIGNATURES_FILE

# Directories
MALWARE_DIR = Path("malware_samples/testing/malware")
BENIGN_DIR = Path("malware_samples/testing/safeware")
OUTPUT_FILE = Path("malware_samples/testing/real_test_results.json")

class ConfusionMatrix:
    def __init__(self):
        self.true_positive = 0
        self.true_negative = 0
        self.false_positive = 0
        self.false_negative = 0

    def add_result(self, actual: str, predicted: str):
        if actual == "malicious" and predicted == "malicious":
            self.true_positive += 1
        elif actual == "benign" and predicted == "benign":
            self.true_negative += 1
        elif actual == "benign" and predicted == "malicious":
            self.false_positive += 1
        elif actual == "malicious" and predicted == "benign":
            self.false_negative += 1

    def accuracy(self):
        total = self.true_positive + self.true_negative + self.false_positive + self.false_negative
        if total == 0: return 0.0
        return (self.true_positive + self.true_negative) / total

    def precision(self):
        denom = self.true_positive + self.false_positive
        if denom == 0: return 0.0
        return self.true_positive / denom

    def recall(self):
        denom = self.true_positive + self.false_negative
        if denom == 0: return 0.0
        return self.true_positive / denom

    def f1_score(self):
        p = self.precision()
        r = self.recall()
        if p + r == 0: return 0.0
        return 2 * (p * r) / (p + r)

    def specificity(self):
        denom = self.true_negative + self.false_positive
        if denom == 0: return 0.0
        return self.true_negative / denom

    def display(self):
        print("\n" + "="*70)
        print("CONFUSION MATRIX - REAL FILES")
        print("="*70)
        print("\n                    Predicted")
        print("                 Malicious    Benign")
        print(f"Actual Malicious    {self.true_positive:4}        {self.false_negative:4}     (Total: {self.true_positive + self.false_negative})")
        print(f"       Benign       {self.false_positive:4}        {self.true_negative:4}     (Total: {self.false_positive + self.true_negative})")
        print()

        total = self.true_positive + self.true_negative + self.false_positive + self.false_negative

        print("="*70)
        print("PERFORMANCE METRICS")
        print("="*70)
        print(f"Total Samples:        {total}")
        print(f"True Positives (TP):  {self.true_positive:4}  (Malware correctly detected)")
        print(f"True Negatives (TN):  {self.true_negative:4}  (Benign correctly identified)")
        print(f"False Positives (FP): {self.false_positive:4}  (Benign flagged as malware) ⚠️")
        print(f"False Negatives (FN): {self.false_negative:4}  (Malware missed) 🚨")
        print()

        print("="*70)
        print("METRICS")
        print("="*70)
        print(f"Accuracy:             {self.accuracy()*100:6.2f}%")
        print(f"Precision:            {self.precision()*100:6.2f}%")
        print(f"Recall (Sensitivity): {self.recall()*100:6.2f}%")
        print(f"F1 Score:             {self.f1_score()*100:6.2f}%")
        print(f"Specificity:          {self.specificity()*100:6.2f}%")
        print("="*70)

        if self.accuracy() >= 0.90:
            print("\n✅ Excellent! Scanner is highly accurate.")
        elif self.accuracy() >= 0.80:
            print("\n✓ Good accuracy. Consider minor tuning.")
        else:
            print("\n⚠️  Needs improvement. Review thresholds and rules.")

        if self.false_negative > 0:
            print(f"🚨 WARNING: {self.false_negative} malware samples were MISSED!")
        if self.false_positive > 0:
            print(f"⚠️  {self.false_positive} benign files were incorrectly flagged")
        print()

def get_files_from_dir(directory: Path, limit: int = 10):
    """Get files from directory, excluding our generated test samples"""
    all_files = []

    # Skip generated test files
    skip_patterns = ['01_', '02_', '03_', '04_', '05_', '06_', '07_', '08_', '09_', '10_']

    for file_path in directory.rglob('*'):
        if file_path.is_file():
            # Skip our generated test samples
            if any(file_path.name.startswith(pattern) for pattern in skip_patterns):
                continue
            # Skip hidden files
            if file_path.name.startswith('.'):
                continue
            all_files.append(file_path)

    # Return up to limit files
    return all_files[:limit]

def main():
    print("="*70)
    print("Testing Scanner on REAL Malware & Benign Files")
    print("="*70)

    # Get real files
    print(f"\n[*] Scanning for real malware samples in: {MALWARE_DIR}")
    malware_files = get_files_from_dir(MALWARE_DIR, limit=10)
    print(f"    Found {len(malware_files)} malware samples")

    print(f"\n[*] Scanning for benign files in: {BENIGN_DIR}")
    benign_files = get_files_from_dir(BENIGN_DIR, limit=10)
    print(f"    Found {len(benign_files)} benign samples")

    if len(malware_files) == 0 or len(benign_files) == 0:
        print("\n❌ Not enough samples found!")
        print(f"   Malware: {len(malware_files)}, Benign: {len(benign_files)}")
        sys.exit(1)

    # Initialize scanner
    print(f"\n[*] Initializing scanner...")
    scanner = LocalMalwareScanner(YARA_RULES_PATH, CUSTOM_SIGNATURES_FILE)

    confusion = ConfusionMatrix()
    results = []

    # Test malware files
    print("\n" + "="*70)
    print("TESTING MALWARE SAMPLES")
    print("="*70)

    for file_path in malware_files:
        print(f"\n[*] Testing: {file_path.name}")
        try:
            result = scanner.scan_file(str(file_path))
            if result:
                predicted = "malicious" if result.is_malicious else "benign"
                correct = (predicted == "malicious")

                confusion.add_result("malicious", predicted)

                results.append({
                    'filename': file_path.name,
                    'actual': 'malicious',
                    'predicted': predicted,
                    'correct': correct,
                    'threat_score': result.threat_score.total_score,
                    'yara_matches': len(result.yara_matches),
                    'detections': len(result.detections)
                })

                if correct:
                    print(f"    ✅ CORRECT - Detected as malicious ({result.threat_score.total_score:.1f}/100)")
                else:
                    print(f"    ❌ MISSED - False negative! Score: {result.threat_score.total_score:.1f}/100")
        except Exception as e:
            print(f"    ❌ Error: {e}")

    # Test benign files
    print("\n" + "="*70)
    print("TESTING BENIGN SAMPLES")
    print("="*70)

    for file_path in benign_files:
        print(f"\n[*] Testing: {file_path.name}")
        try:
            result = scanner.scan_file(str(file_path))
            if result:
                predicted = "malicious" if result.is_malicious else "benign"
                correct = (predicted == "benign")

                confusion.add_result("benign", predicted)

                results.append({
                    'filename': file_path.name,
                    'actual': 'benign',
                    'predicted': predicted,
                    'correct': correct,
                    'threat_score': result.threat_score.total_score,
                    'yara_matches': len(result.yara_matches),
                    'detections': len(result.detections)
                })

                if correct:
                    print(f"    ✅ CORRECT - Identified as benign ({result.threat_score.total_score:.1f}/100)")
                else:
                    print(f"    ❌ FALSE POSITIVE - Flagged benign file! Score: {result.threat_score.total_score:.1f}/100")
        except Exception as e:
            print(f"    ❌ Error: {e}")

    # Display confusion matrix
    confusion.display()

    # Show incorrect predictions
    incorrect = [r for r in results if not r['correct']]
    if incorrect:
        print("\n" + "="*70)
        print(f"INCORRECT PREDICTIONS ({len(incorrect)})")
        print("="*70)
        for r in incorrect:
            print(f"\n{r['filename']}")
            print(f"  Actual: {r['actual']}, Predicted: {r['predicted']}")
            print(f"  Score: {r['threat_score']:.1f}/100")
            print(f"  YARA: {r['yara_matches']}, Detections: {r['detections']}")

    # Save results
    output_data = {
        'confusion_matrix': {
            'true_positive': confusion.true_positive,
            'true_negative': confusion.true_negative,
            'false_positive': confusion.false_positive,
            'false_negative': confusion.false_negative
        },
        'metrics': {
            'accuracy': confusion.accuracy(),
            'precision': confusion.precision(),
            'recall': confusion.recall(),
            'f1_score': confusion.f1_score(),
            'specificity': confusion.specificity()
        },
        'detailed_results': results
    }

    with open(OUTPUT_FILE, 'w') as f:
        json.dump(output_data, f, indent=2)

    print(f"\n[+] Results saved to: {OUTPUT_FILE}")
    print("\n✅ Testing complete!")

if __name__ == "__main__":
    main()
