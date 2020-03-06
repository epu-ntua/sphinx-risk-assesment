#Sphinx Risk Assessment
This is the git repository for the RCRA module of the Sphinx project

#Installation Guide - For developers working on Pycharm

##Prerequisites

*  Download and install latest python3 - https://www.python.org/downloads/
*  Download and install Pycharm IDE - https://www.jetbrains.com/pycharm/

##Installing Risk Assesment Flask 
From Pycharms' starting screen

* Check out from Version Control ->Git
*  Copy the url "https://sphinx-repo.intracom-telecom.com/sphinx-project/real-time-cyber-risk-assessment/riskassessmentflask "url into "Git Repository URL"
*  Press test and enter gitlab credentials if needed
*  Clone
*  Create new virtual environment (File -> Settings -> Project -> Project Intepreter => icon -> Add local -> ok)
*  Install requirements from requirements.txt (Go to requirements.txt -> Press install on pop up)

Current Database used is Sqlite but it isn't included in github due to size
In fresh installs always recreate database 
#Running Risk Assessment Module
`flask db migrate` (Shouldn't be needed)
`flask db upgrade` (Necessary to recreate db)
`flask run`