from flask import render_template, request, redirect, jsonify, Response, flash
from multiprocessing import Process
from app.producer import *
from app.globals import *
from app.utils import *
from app.forms import *
from app import app

@app.route('/repo/dashboard/asset/', methods=['GET', 'POST'])
def repo_dashboard_asset():
    if request.method == 'POST':
        return redirect("/repo/dashboard/asset/")
    else:
        # assetsArray = get_assetsfromrepository()
        # if assetsArray != -1:
        #     return render_template('asset_dashboard.html', assets=assetsArray)
        # else:
        repo_assets = [
            {
                "id": "1",
                "name": "Asset1",
                "location": "Group1",
                "Verified": "false",
                "mac_address": "xx:xx:xx:xx",
                "ip": "xxx.xxx.xxx.xxx",
                "last_touch_date": "today",
            }
        ]
        print(repo_assets)
        return render_template('templates_dashboard/repo_asset_dashboard.html', repo_assets=repo_assets)


@app.route('/repo/dashboard/threat/', methods=['GET', 'POST'])
def repo_dashboard_threat():
    if request.method == 'POST':
        return redirect("/repo/dashboard/threat/")
    else:
        # assetsArray = get_assetsfromrepository()
        # if assetsArray != -1:
        #     return render_template('asset_dashboard.html', assets=assetsArray)
        # else:
        repo_threats = [
            {
                "id": "1",
                "name": "1",
                "capec": "1",
                "cwe": "1"
            }
        ]
        print(repo_threats)
        return render_template('templates_dashboard/repo_threat_dashboard.html', repo_threats=repo_threats)


@app.route('/repo/dashboard/risk/objectives/', methods=['GET', 'POST'])
# @app.route('/repo/dashboard/risk/objectives/threat/<threat_id>/asset/<asset_id>/', methods=['GET', 'POST'])
def repo_dashboard_risk_objectives():
    if request.method == 'POST':
        return redirect("/repo/dashboard/risk/objectives/")
    else:
        # assetsArray = get_assetsfromrepository()
        # if assetsArray != -1:
        #     return render_template('asset_dashboard.html', assets=assetsArray)
        # else:
        repo_threats = [
            {
                "likelihood": "Certain",
                "monetary": "(Low) No monetary loss",
                "confidentiality": "(Low) No records leaked",
                "integrity": "(Low) No records lost or altered",
                "availability": "(Low) No disruption of services",
                "safety": "-"
            },
            {
                "likelihood": "Possible",
                "monetary": "-",
                "confidentiality": "-",
                "integrity": "-",
                "availability": "-",
                "safety": "(Low) No injuries or fatalities likely"
            },
            {
                "likelihood": "Rare",
                "monetary": "-",
                "confidentiality": "-",
                "integrity": "(Medium) Some records lost or altered",
                "availability": "(Medium) Some disruption of services",
                "safety": "(Medium) Injuries are likely"
            },
            {
                "likelihood": "Rare than Rare",
                "monetary": "(High) Significant monetary loss",
                "confidentiality": "(High) Many records leaked",
                "integrity": "(High) Many records lost or altered",
                "availability": "-",
                "safety": "-"
            },
            {
                "likelihood": "Oddness 3 or higher",
                "monetary": "(Medium) Some monetary loss",
                "confidentiality": "(Medium) Some records leaked",
                "integrity": "-",
                "availability": "(High) Significant disruption of services",
                "safety": "(High) Fatalities are likley"
            }
        ]
        print(repo_threats)
        return render_template('templates_dashboard/repo_risk_objectives_dashboard.html', repo_threats=repo_threats)


@app.route('/repo/dashboard/vulnerability/', methods=['GET', 'POST'])
def repo_dashboard_vulnerability():
    if request.method == 'POST':
        return redirect("/repo/dashboard/vulnerability/")
    else:
        # assetsArray = get_assetsfromrepository()
        # if assetsArray != -1:
        #     return render_template('asset_dashboard.html', assets=assetsArray)
        # else:
        repo_vulnerabilities = [
            {
                "id": "1",
                "name": "1",
                "location": "1",
                "Verified": "1",
                "mac_address": "1",
                "ip": "1",
                "last_touch_date": "1",
            }
        ]
        print(repo_vulnerabilities)
        return render_template('templates_dashboard/repo_vulnerability_dashboard.html', repo_vulnerabilities=repo_vulnerabilities)
