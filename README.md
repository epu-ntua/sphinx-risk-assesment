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

#Running with docker compose
*  Install docker-compose ("https://docs.docker.com/compose/install/"). If on windows and got docker desktop it is already installed
*  From command line:
*  Move to folder "docker"
*  Run `docker-compose up -d --build`
*  To stop it: `docker-compose down`

#To produce kubernetes yaml automatically.
* Install Kompose ("https://kompose.io/")
* If on windows simply download executable, rename to kompose and move it to system32 folder or add to path
* From commnd line
* Move to folder docker
* Run `kompose convert`
* Pre produced yaml can be found in docker file