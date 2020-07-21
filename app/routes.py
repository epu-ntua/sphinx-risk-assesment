from app import app
from flask import render_template, request, redirect
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


@app.route('/assets/', defaults={"asset": -1})
@app.route('/assets/<asset>/', methods=['GET', 'POST'])
def assets(asset):
    if request.method == 'POST':
        if asset != -1:
            print(request.form)

            toRedirect = "vulnerabilities/"
            return redirect(toRedirect)
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

        return render_template('assets.html', asset=asset, assets=assetsArray, proposedCVEArray=proposedCVEArray,
                               othersCVEArray=othersCVEArray)


@app.route('/assets/<asset>/vulnerabilities/', defaults={"asset": -1, "vulnerability": -1})
@app.route('/assets/<asset>/vulnerabilities/<vulnerability>/', methods=['GET', 'POST'])
def vulnerabilities(asset, vulnerability):
    if request.method == 'POST':
        i = 5
        toRedirect = "threats/"
        return redirect(toRedirect)
    else:
        assetsArray = get_assets()
        print(assetsArray[0].VReport_assetID)

        return render_template('vulnerabilities.html', asset=asset, vulnerability=vulnerability, assets=assetsArray)


@app.route('/assets/<asset>/vulnerabilities/<vulnerability>/threats/',
           defaults={"asset": -1, "vulnerability": -1, "threat": -1})
@app.route('/assets/<asset>/vulnerabilities/<vulnerability>/threats/<threat>/', methods=['GET', 'POST'])
def threats(asset, vulnerability, threat):
    if request.method == 'POST':
        i = 5
    else:
        assetsArray = get_assets()
        print(assetsArray[0].VReport_assetID)

        return render_template('threats.html', asset=asset, vulnerability=vulnerability, threat=threat,
                               assets=assetsArray)


@app.route('/gira_assess/' , methods=['GET', 'POST'])
def gira_assess():
    if request.method == 'POST':
        return redirect("/gira_assess/")
    else:
        return render_template('gira_assess.html' )



@app.route('/gira_assess/gira_assess_exposure/' , methods=['GET', 'POST'])
def gira_assess_exposure():
    if request.method == 'POST':
        return redirect("/gira_assess_exposure/")
    else:
        return render_template('gira_assess_exposure.html' )

@app.route('/gira_assess/gira_assess_response/' , methods=['GET', 'POST'])
def gira_assess_response():
    if request.method == 'POST':
        return redirect("/gira_assess/gira_assess_response/")
    else:
        return render_template('gira_assess_response.html' )

@app.route('/gira_assess/gira_assess_materialisation/' , methods=['GET', 'POST'])
def gira_assess_materialisation():
    if request.method == 'POST':
        return redirect("/gira_assess/gira_assess_materialisation/")
    else:
        return render_template('gira_assess_materialisation.html' )



@app.route('/gira_assess/gira_assess_consequence/' , methods=['GET', 'POST'])
def gira_assess_consequence():
    if request.method == 'POST':
        return redirect("/gira_assess/gira_assess_consequence/")
    else:
        return render_template('gira_assess_consequence.html' )



@app.route('/gira_assess/gira_assess_asset_status/' , methods=['GET', 'POST'])
def gira_assess_asset_status():
    if request.method == 'POST':
        return redirect("/gira_assess/gira_assess_asset_status/")
    else:
        return render_template('gira_assess_asset_status.html' )

@app.route('/gira_assess/gira_assess_asset_impact/' , methods=['GET', 'POST'])
def gira_assess_asset_impact():
    if request.method == 'POST':
        return redirect("/gira_assess/gira_assess_asset_impact/")
    else:
        return render_template('gira_assess_asset_impact.html' )

@app.route('/gira_assess/gira_assess_objective/' , methods=['GET', 'POST'])
def gira_assess_objective():
    if request.method == 'POST':
        return redirect("/gira_assess/gira_assess_objective/")
    else:
        return render_template('gira_assess_objective.html' )



@app.route('/gira_overview/' , methods=['GET', 'POST'])
def gira_overview():
    if request.method == 'POST':
        return redirect("/gira_overview/")
    else:
        return render_template('gira_overview.html')


@app.route('/gira_overview/gira_threat_exposure/', methods=['GET', 'POST'])
def gira_threat_exposure():
    if request.method == 'POST':
        return redirect("/gira_overview/")
    else:
        return render_template('gira_threat_exposure.html')


@app.route('/gira_overview/gira_threat_response/', methods=['GET', 'POST'])
def gira_threat_response():
    if request.method == 'POST':
        return redirect("/gira_overview/")
    else:
        return render_template('gira_threat_response.html')


@app.route('/gira_overview/gira_threat_materialisation/', methods=['GET', 'POST'])
def gira_threat_materialisation():
    if request.method == 'POST':
        return redirect("/gira_overview/")
    else:
        return render_template('gira_threat_materialisation.html')


@app.route('/gira_overview/gira_consequence/', methods=['GET', 'POST'])
def gira_consequence():
    if request.method == 'POST':
        return redirect("/gira_overview/")
    else:
        return render_template('gira_consequences.html')


@app.route('/gira_overview/gira_asset_status/', methods=['GET', 'POST'])
def gira_asset_status():
    if request.method == 'POST':
        return redirect("/gira_overview/")
    else:
        return render_template('gira_asset_status.html')


@app.route('/gira_overview/gira_asset_impact/', methods=['GET', 'POST'])
def gira_asset_impact():
    if request.method == 'POST':
        return redirect("/gira_overview/")
    else:
        return render_template('gira_asset_impact.html')


@app.route('/gira_overview/gira_objective/', methods=['GET', 'POST'])
def gira_objective():
    if request.method == 'POST':
        return redirect("/gira_overview/")
    else:
        return render_template('gira_objective.html')


@app.route('/gira_overview/gira_result/', methods=['GET', 'POST'])
def gira_result():
    if request.method == 'POST':
        return redirect("/gira_overview/")
    else:
        return render_template('gira_result.html')


@app.route('/asset_dashboard/', methods=['GET', 'POST'])
def asset_dashboard():
    if request.method == 'POST':
        return redirect("/asset_dashboard/")
    else:
        # assetsArray = get_assetsfromrepository()
        # if assetsArray != -1:
        #     return render_template('asset_dashboard.html', assets=assetsArray)
        # else:
        return render_template('asset_dashboard.html')


@app.route('/general_dashboard/asset_view/', defaults={"asset": -1})
@app.route('/general_dashboard/asset_view/<asset>/', methods=['GET', 'POST'])
def general_dashboard_asset_view(asset):
    if request.method == 'POST':
        i = 5
        toRedirect = "/general_dashboard/asset_view/"
        return redirect(toRedirect)
    else:
        # assetsArray = get_assets()

        # print(assetsArray[0].VReport_assetID)
        assetsArray = []
        return render_template('general_dashboard_asset_view.html', asset=asset, assets=assetsArray)


@app.route('/general_dashboard/threat_view/', defaults={"threat": -1})
@app.route('/general_dashboard/threat_view/<threat>/', methods=['GET', 'POST'])
def general_dashboard_threat_view(threat):
    if request.method == 'POST':
        i = 5
        toRedirect = "/general_dashboard/threat_view/"
        return redirect(toRedirect)
    else:
        # assetsArray = get_assets()

        # print(assetsArray[0].VReport_assetID)
        assetsArray = []
        return render_template('general_dashboard_threat_view.html', threat=threat, assets=assetsArray)

@app.route('/general_dashboard/tree_view/', defaults={"threat": -1})
@app.route('/general_dashboard/tree_view/<threat>/', methods=['GET', 'POST'])
def general_dashboard_tree_view(threat):
    if request.method == 'POST':
        i = 5
        toRedirect = "/general_dashboard/threat_view/"
        return redirect(toRedirect)
    else:
        # assetsArray = get_assets()

        # print(assetsArray[0].VReport_assetID)
        assetsArray = []
        return render_template('general_dashboard_tree_view.html', threat=threat, assets=assetsArray)


@app.route('/test_gd')
def test_gd():
    return render_template('test_gd.html')

