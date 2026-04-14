# Authentication Security Analysis

## Description
This project analyzes authentication logs and detects suspicious login behavior and token-based attacks using Python.

## Features
- Detection of failed login patterns
- Identification of abnormal login times
- Detection of suspicious IP activity
- Analysis of authentication success/failure ratio
- Basic anomaly detection using machine learning (LOF)

## Technologies
- Python
- Pandas
- Matplotlib
- Scikit-learn

## Dataset
Sample dataset: security_auth_logs.csv

## How it works
- Reads authentication logs from CSV file
- Processes login timestamps and IP addresses
- Calculates failed login ratios
- Detects anomalies using Local Outlier Factor (LOF)
- Highlights suspicious login activity

## Output
- Suspicious IP addresses
- Failed login statistics
- Login activity by time
- Visual charts of anomalies

## Project Goal
To demonstrate detection of suspicious authentication behavior and basic security analytics.
