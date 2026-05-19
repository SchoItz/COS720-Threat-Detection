COS720 Technical Documentation:
Francois Scholtz- U19024232
System Overview:
The prototype is a full-stack program that uses a CSV file to find abnormal employee behavior and classify it as Malicious or Normal using Random Forest machine learning.
Architecture:
•	Web based Client using react
•	Application layer using Python 3 Flask
•	Scikit-learn for machine learning
•	File system for storage .json files
Software Requirements and dependencies:
Backend requirements: 	Frontend requirements
Package	Version
Python	3.10 or higher
Flask	3.0.3
flask-cors	4.0.1
pandas	2.2.2
numpy	1.26.4
scikit-learn	1.5.1
joblib	1.4.2
matplotlib	3.9.1
seaborn	0.13.2
Werkzeug	3.0.3
Package	Version
react	18.3.1
react-dom	18.3.1
react-router-dom	6.26.1
react-scripts	5.0.1
ajv	8.20.0
concurrently	9.2.1
Dataset:
The system requires a Kaggle dataset:
Name: Insider Threat Dataset
Subtitle:Behavioral Features & Threat Classification Dataset for Security Assessment
Link to dataset: Dataset URL
Filename: insider_threat_clean_dataset.csv
Location: prototype/data/insider_threat_clean_dataset.csv
Installation Instructions
Run this command in cmd:
•	Git clone 
•	Cd COS720-Threat-Detection/prototype
Install Pythong dependencies using this command:
•	pip install -r requirements.txt
Download the dataset and place it into the correct folder location so its path looks like this:
•	prototype/data/insider_threat_clean_dataset.csv
Train your model from prototype/backend/:
•	Python train_model.py
This should have output files written to prototype/models/:
Confirm these files exist:
•	prototype/models/rf_model.pkl
•	prototype/models/preprocessor.pkl
•	prototype/models/thresholds.json
•	prototype/models/feature_names.json
•	prototype/models/model_config.json
Deployment and execution
To start and deploy the prototype navigate to prototype/backend/ and run:
•	python app.py
•	navigate to http://localhost:5000
ALT:
Navigate to prototype/frontend/ and use command:
•	npm run build
•	npm start
•	navigate to http://localhost:3000
•	NOTE: This only starts the react client and does not run the server that should already be running python app.py
To stop the server press Control + C in the terminal running the app.py
To stop the react app press Control + C in the terminal running npm start
If you did not run the Trained model then it will run in a Demo mode with default values and won’t be the Random Forest values. You can train a model through the react client.

Source code documentation
This is the source code on GitHub: Link to Github Repository
This is the source code on Google Drive: Link to Google Drive
 
Trained model files
All the trained models are created in prototype/models/.
They are created by running the python train_model.py.
Demonstrating prototype functionality
 
 

 
 
 
 
 
   
 
 
