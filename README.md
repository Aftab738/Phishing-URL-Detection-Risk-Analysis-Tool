
# Phishing URL Detection and Risk Analysis Tool

This project is a web-based tool that helps users check whether a URL is safe or not. It looks at different parts of a URL and tries to find signs of phishing or fake websites.

Instead of using complex machine learning, this project uses a simple rule-based approach. It checks for things like suspicious keywords, unusual domain patterns, repeated characters, and cases where popular websites are being copied.


## What this project does

* Takes a URL as input
* Analyzes the structure of the URL
* Checks for suspicious patterns and keywords
* Detects possible brand impersonation
* Generates a risk score (0–100)
* Classifies the URL as:

  * Safe
  * Suspicious
  * Dangerous
* Shows reasons for the result
* Suggests the official website if a fake one is detected


## Tech used

* Python
* Flask
* HTML
* CSS
* JavaScript

### Libraries

* requests
* re
* urllib.parse


## How it works

* User enters a URL
* The system processes and analyzes it
* Various checks are applied (keywords, domain, patterns, etc.)
* A risk score is calculated
* The URL is classified and the result is shown


## Features

* Simple and easy to use interface
* Fast results without heavy processing
* Clear explanation of why a URL is risky
* Works without any external database


## How to run

* Clone the repository
* Install required libraries
* Run the Flask app
* Open the app in your browser
* Enter a URL and check the result

---

