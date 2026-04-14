# Authentication Security Analysis

## Description
This project analyzes authentication logs to detect suspicious login activity and potential token-based attacks using Python.

## Features
- Detection of failed login patterns
- Identification of unusual login times
- Detection of suspicious IP activity
- Analysis of success/failure login ratio
- Basic anomaly detection using Local Outlier Factor (LOF)

## Technologies
- Python
- Pandas
- Matplotlib
- Scikit-learn

## Dataset
Sample dataset: `security_auth_logs.csv`

## How it works
- Reads authentication logs from a CSV file
- Extracts time-based features (e.g., login hour)
- Calculates failed login ratios per IP
- Applies anomaly detection (LOF)
- Identifies potentially suspicious behavior

## Output
- List of suspicious IP addresses
- Failed login statistics
- Login activity by time
- Visual charts

## Project Goal
To demonstrate basic techniques for detecting suspicious authentication behavior in security logs.
