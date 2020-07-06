from app import app
from flask import render_template,request ,redirect
import flask
from app.utils import *
from app.globals import *

@app.context_processor
def serverInfo():
    return dict(serverAddress=serverAddress, serverPort=serverPort)



@app.route('/')
@app.route('/home')
def entry_page():
    return render_template('entry_page.html')

@app.route('/assets/' ,defaults={"asset": -1})
@app.route('/assets/<asset>/' , methods=['GET', 'POST'])
def assets(asset):
    if request.method == 'POST':
        if asset != -1:
            print(request.form)

            toRedirect = "vulnerabilities/"
            return redirect( toRedirect)
        else:
            return redirect("/assets/")
    else:
        assetsArray = get_assets()
        # print(assetsArray[0].VReport_assetID)

        proposedCVEArray = []
        # print(assetsArray)
        if assetsArray != -1:
            for tempAsset in assetsArray:
                proposedCVEArray.append(get_cve_recommendations(tempAsset.VReport_assetID))


        # Still need an fuction that will get the other CVE, or preferably being able to add CVE one by one by hand
        othersCVEArray = []
        # for tempAsset in assetsArray:
            # othersCVEArray.append()

        return render_template('assets.html', asset = asset , assets = assetsArray , proposedCVEArray = proposedCVEArray ,othersCVEArray = othersCVEArray)

@app.route('/assets/<asset>/vulnerabilities/', defaults={"asset": -1 ,"vulnerability" : -1})
@app.route('/assets/<asset>/vulnerabilities/<vulnerability>/' , methods=['GET', 'POST'])
def vulnerabilities(asset, vulnerability):
    if request.method == 'POST':
        i = 5
    else:
        assetsArray = get_assets()
        print(assetsArray[0].VReport_assetID)


        return render_template('vulnerabilities.html', asset = asset, vulnerability = vulnerability, assets = assetsArray)

@app.route('/assets/<asset>/vulnerabilities/<vulnerability>/threats/' , defaults={"asset": -1 ,"vulnerability" : -1, "threat": -1})
@app.route('/assets/<asset>/vulnerabilities/<vulnerability>/threats/<threat>/' , methods=['GET', 'POST'])
def threats(asset, vulnerability,threat):
    if request.method == 'POST':
        i = 5
    else:
        assetsArray = get_assets()
        print(assetsArray[0].VReport_assetID)

        return render_template('threats.html' ,asset = asset, vulnerability = vulnerability , threat = threat, assets = assetsArray)

@app.route('/gira_overview/' , methods=['GET', 'POST'])
def gira_overview():
    if request.method == 'POST':
        return redirect("/gira_overview/")
    else:
        return render_template('gira_overview.html')


@app.route('/test_gd')
def test_gd():
    return render_template('test_gd.html')