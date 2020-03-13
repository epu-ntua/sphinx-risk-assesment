from app import app
from flask import render_template,request ,redirect
import flask

@app.route('/')
@app.route('/home')
def entry_page():
    return render_template('entry_page.html')

@app.route('/assets/' ,defaults={"asset": -1})
@app.route('/assets/<int:asset>/' , methods=['GET', 'POST'])
def assets(asset):
    if request.method == 'POST':
        if asset != -1:
            print(request.form)

            toRedirect = "vulnerabilities/"
            return redirect( toRedirect)
        else:
            return redirect("/assets/")
    else:
        assetsArray = [ 1 , 2 ,3 ]
        proposedCVEArray = [ 1 , 2 ,3 ]
        othersCVEArray = [ 4 , 5 ]

        return render_template('assets.html', asset = asset , assets = assetsArray , proposedCVEArray = proposedCVEArray ,othersCVEArray = othersCVEArray)

@app.route('/assets/<int:asset>/vulnerabilities/', defaults={"asset": -1 ,"vulnerability" : -1})
@app.route('/assets/<int:asset>/vulnerabilities/<int:vulnerability>/' , methods=['GET', 'POST'])
def vulnerabilities(asset, vulnerability):
    if request.method == 'POST':
        i = 5
    else:
        return render_template('vulnerabilities.html', asset = asset, vulnerability = vulnerability)

@app.route('/assets/<int:asset>/vulnerabilities/<int:vulnerability>/threats/' , defaults={"asset": -1 ,"vulnerability" : -1, "threat": -1})
@app.route('/assets/<int:asset>/vulnerabilities/<int:vulnerability>/threats/<int:threat>/' , methods=['GET', 'POST'])
def threats(asset, vulnerability,threat):
    if request.method == 'POST':
        i = 5
    else:
        return render_template('threats.html' ,asset = asset, vulnerability = vulnerability , threat = threat )

@app.route('/test_gd')
def test_gd():
    return render_template('test_gd.html')