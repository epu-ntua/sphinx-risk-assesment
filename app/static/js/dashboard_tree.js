config = {
    container: "#tree-simple",
    // animateOnInit: true,
    levelSeparation: 200,
    siblingSeparation: 50,
    connectors: {
        type: "bCurve"
    },
    node: {
        collapsable: true
    }
};

threat_exposure_node = {
    text: {name: "Threat exposure"},
    innerHTML:
        '<div class="card bg-light mb-3 custom-dashboard-single-asset-card" style="max-width: 18rem;">\n' +
        '                <div class="card-header"> Threat Node</div>\n' +
        '                <div class="card-body">\n' +
        '                    <h5 class="card-title">Description</h5>\n' +
        '                    <p class="card-text"> Lorem Ipsum --- </p>\n' +
        '                    <h5 class="card-title"> Calculated Occurance Risk</h5>\n' +
        '                    <p class="card-text"> 45% </p>\n' +
        '                </div>\n' +
        '            </div>'
}

pre_incident_response_node = {
    parent: threat_exposure_node,
    text: {name: "Pre Incident Response"},
    innerHTML: '<div class="card bg-light mb-3 custom-dashboard-single-asset-card" style="max-width: 18rem;">\n' +
        '                    <div class="card-header"> Response Node #2:\n' +
        '                        Added Security Software xxx\n' +
        '                    </div>\n' +
        '                    <div class="card-body">\n' +
        '                        <h5 class="card-title">Description</h5>\n' +
        '                        <p class="card-text"> Lorem Ipsum --- </p>\n' +
        '                        <h5 class="card-title">Incident Probability Effect (Positive)</h5>\n' +
        '                        <p class="card-text"> Major Impact </p>\n' +
        '                    </div>\n' +
        '                </div>'
}

incident_materialisation_node = {
    parent: threat_exposure_node,
    text: {name: "Incident Materialisation"},
    innerHTML: '<table class="table  table-bordered">\n' +
        '                    <thead>\n' +
        '                    <tr>\n' +
        '                        <th scope="col" class="custom-table-header" colspan="5"> Incident Materialisation Node</th>\n' +
        '\n' +
        '                    </tr>\n' +
        '                    <tr>\n' +
        '                        <th scope="col" class="custom-table-header"> Threat Realisation</th>\n' +
        '                        <th scope="col" class="custom-table-header" colspan="2"> Occurs</th>\n' +
        '                        <th scope="col" class="custom-table-header" colspan="2"> Averted</th>\n' +
        '\n' +
        '                    </tr>\n' +
        '                    </thead>\n' +
        '                    <thead class="thead-light">\n' +
        '                    <tr>\n' +
        '                        <th scope="col" class="custom-table-header"> Response</th>\n' +
        '                        <th scope="col" class="custom-table-header"> 1#</th>\n' +
        '                        <th scope="col" class="custom-table-header"> 2#</th>\n' +
        '                        <th scope="col" class="custom-table-header"> 1#</th>\n' +
        '                        <th scope="col" class="custom-table-header"> 2#</th>\n' +
        '                    </tr>\n' +
        '                    </thead>\n' +
        '                    <tbody>\n' +
        '                    <tr>\n' +
        '                        <th scope="row">Incident 1# Confidentiality</th>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                    </tr>\n' +
        '                    <tr>\n' +
        '                        <th scope="row">Incident 2# Integrity</th>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                    </tr>\n' +
        '                    <tr>\n' +
        '                        <th scope="row">Incident 3# Authentication</th>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                    </tr>\n' +
        '                    </tbody>\n' +
        '                </table>'
}

post_incident_response_node = {
    parent: incident_materialisation_node,
    text: {name: "Post Incident Response"},
    innerHTML: '<div class="card bg-light mb-3 custom-dashboard-single-asset-card" style="max-width: 18rem;">\n' +
        '                    <div class="card-header"> Response Node #2:\n' +
        '                        Added Security Software xxx\n' +
        '                    </div>\n' +
        '                    <div class="card-body">\n' +
        '                        <h5 class="card-title">Description</h5>\n' +
        '                        <p class="card-text"> Lorem Ipsum --- </p>\n' +
        '                        <h5 class="card-title">Incident Probability Effect (Positive)</h5>\n' +
        '                        <p class="card-text"> Major Impact </p>\n' +
        '                    </div>\n' +
        '                </div>'
}

consequence_node = {
    parent: incident_materialisation_node,
    text: {name: "Consequence"},
    innerHTML: '<table class="table  table-bordered">\n' +
        '                    <thead>\n' +
        '                    <tr>\n' +
        '                        <th scope="col" class="custom-table-header" colspan="7"> Consequence Node</th>\n' +
        '\n' +
        '                    </tr>\n' +
        '                    <tr>\n' +
        '                        <th scope="col" class="custom-table-header"> Incident</th>\n' +
        '                        <th scope="col" class="custom-table-header" colspan="2"> 1# Confidentiality</th>\n' +
        '                        <th scope="col" class="custom-table-header" colspan="2"> 2# Integrity</th>\n' +
        '                        <th scope="col" class="custom-table-header" colspan="2"> 3# Authentication</th>\n' +
        '                    </tr>\n' +
        '                    </thead>\n' +
        '                    <thead class="thead-light">\n' +
        '                    <tr>\n' +
        '                        <th scope="col" class="custom-table-header"> Response</th>\n' +
        '                        <th scope="col" class="custom-table-header"> 1#</th>\n' +
        '                        <th scope="col" class="custom-table-header"> 2#</th>\n' +
        '                        <th scope="col" class="custom-table-header"> 1#</th>\n' +
        '                        <th scope="col" class="custom-table-header"> 2#</th>\n' +
        '                        <th scope="col" class="custom-table-header"> 1#</th>\n' +
        '                        <th scope="col" class="custom-table-header"> 2#</th>\n' +
        '                    </tr>\n' +
        '                    </thead>\n' +
        '                    <tbody>\n' +
        '                    <tr>\n' +
        '                        <th scope="row">Consequence 1# Modify Data</th>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                    </tr>\n' +
        '                    <tr>\n' +
        '                        <th scope="row">Consequence 2# Gain Privileges</th>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                    </tr>\n' +
        '                    <tr>\n' +
        '                        <th scope="row">Consequence 3# Execute Unauthorized Commands</th>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                    </tr>\n' +
        '                    </tbody>\n' +
        '                </table>'
}

impact_on_asset_node = {
    parent: consequence_node,
    text: {name: "Impact on asset "},
    innerHTML: '<h3> Asset: IT department Equipment</h3>\n' +
        '                <table class="table  table-bordered">\n' +
        '                    <thead>\n' +
        '                    <tr>\n' +
        '                        <th scope="col" class="custom-table-header" colspan="10"> Impact on Asset Node #1</th>\n' +
        '\n' +
        '                    </tr>\n' +
        '                    <tr>\n' +
        '                        <th scope="col" class="custom-table-header"> Consequence</th>\n' +
        '                        <th scope="col" class="custom-table-header" colspan="3">Modify Data</th>\n' +
        '                        <th scope="col" class="custom-table-header" colspan="3">Gain Privilege</th>\n' +
        '                        <th scope="col" class="custom-table-header" colspan="3">Unauthorised Command</th>\n' +
        '                    </tr>\n' +
        '                    </thead>\n' +
        '                    <thead class="thead-light">\n' +
        '                    <tr>\n' +
        '                        <th scope="col" class="custom-table-header"> State</th>\n' +
        '                        <th scope="col" class="custom-table-header">In use</th>\n' +
        '                        <th scope="col" class="custom-table-header">Online</th>\n' +
        '                        <th scope="col" class="custom-table-header">Offline</th>\n' +
        '                        <th scope="col" class="custom-table-header">In use</th>\n' +
        '                        <th scope="col" class="custom-table-header">Online</th>\n' +
        '                        <th scope="col" class="custom-table-header">Offline</th>\n' +
        '                        <th scope="col" class="custom-table-header">In use</th>\n' +
        '                        <th scope="col" class="custom-table-header">Online</th>\n' +
        '                        <th scope="col" class="custom-table-header">Offline</th>\n' +
        '                    </tr>\n' +
        '                    </thead>\n' +
        '                    <tbody>\n' +
        '                    <tr>\n' +
        '                        <th scope="row">Impact:Available</th>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                    </tr>\n' +
        '                    <tr>\n' +
        '                        <th scope="row">Impact:Defective</th>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                    </tr>\n' +
        '                    <tr>\n' +
        '                        <th scope="row">Impact:Broken</th>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                    </tr>\n' +
        '                    </tbody>\n' +
        '                </table>'
}

impact_on_asset_node_1 = {
    parent: consequence_node,
    text: {name: "Impact on asset "},
    innerHTML: '<h3> Asset: IT department Equipment</h3>\n' +
        '                <table class="table  table-bordered">\n' +
        '                    <thead>\n' +
        '                    <tr>\n' +
        '                        <th scope="col" class="custom-table-header" colspan="10"> Impact on asset Node#2</th>\n' +
        '\n' +
        '                    </tr>\n' +
        '                    <tr>\n' +
        '                        <th scope="col" class="custom-table-header"> Consequence</th>\n' +
        '                        <th scope="col" class="custom-table-header" colspan="3">Modify Data</th>\n' +
        '                        <th scope="col" class="custom-table-header" colspan="3">Gain Privilege</th>\n' +
        '                        <th scope="col" class="custom-table-header" colspan="3">Unauthorised Command</th>\n' +
        '                    </tr>\n' +
        '                    </thead>\n' +
        '                    <thead class="thead-light">\n' +
        '                    <tr>\n' +
        '                        <th scope="col" class="custom-table-header"> State</th>\n' +
        '                        <th scope="col" class="custom-table-header">In use</th>\n' +
        '                        <th scope="col" class="custom-table-header">Online</th>\n' +
        '                        <th scope="col" class="custom-table-header">Offline</th>\n' +
        '                        <th scope="col" class="custom-table-header">In use</th>\n' +
        '                        <th scope="col" class="custom-table-header">Online</th>\n' +
        '                        <th scope="col" class="custom-table-header">Offline</th>\n' +
        '                        <th scope="col" class="custom-table-header">In use</th>\n' +
        '                        <th scope="col" class="custom-table-header">Online</th>\n' +
        '                        <th scope="col" class="custom-table-header">Offline</th>\n' +
        '                    </tr>\n' +
        '                    </thead>\n' +
        '                    <tbody>\n' +
        '                    <tr>\n' +
        '                        <th scope="row">Impact:Available</th>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                    </tr>\n' +
        '                    <tr>\n' +
        '                        <th scope="row">Impact:Defective</th>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                    </tr>\n' +
        '                    <tr>\n' +
        '                        <th scope="row">Impact:Broken</th>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                    </tr>\n' +
        '                    </tbody>\n' +
        '                </table>'
}

objective_node = {
    parent: impact_on_asset_node,
    text: {name: "Objective"},
    innerHTML: '<table class="table  table-bordered">\n' +
        '                    <thead>\n' +
        '                    <tr>\n' +
        '                        <th scope="col" class="custom-table-header" colspan="5"> Objective Node #1</th>\n' +
        '\n' +
        '                    </tr>\n' +
        '                    <tr>\n' +
        '                        <th scope="col" class="custom-table-header"> Asset:Consequence</th>\n' +
        '                        <th scope="col" class="custom-table-header" colspan="3"> IT Department Equipment: Modify data\n' +
        '                        </th>\n' +
        '                        <th scope="col" class="custom-table-header"> ....\n' +
        '                        </th>\n' +
        '                    </tr>\n' +
        '                    </thead>\n' +
        '                    <thead class="thead-light">\n' +
        '                    <tr>\n' +
        '                        <th scope="col" class="custom-table-header"> Impact</th>\n' +
        '                        <th scope="col" class="custom-table-header" colspan="3"> Defective</th>\n' +
        '                        <th scope="col" class="custom-table-header"> ....</th>\n' +
        '                    </tr>\n' +
        '                    </thead>\n' +
        '                    <thead class="thead-light">\n' +
        '                    <tr>\n' +
        '                        <th scope="col" class="custom-table-header"> State</th>\n' +
        '                        <th scope="col" class="custom-table-header"> In use</th>\n' +
        '                        <th scope="col" class="custom-table-header"> Online</th>\n' +
        '                        <th scope="col" class="custom-table-header"> Offline</th>\n' +
        '                        <th scope="col" class="custom-table-header"> ...</th>\n' +
        '\n' +
        '                    </tr>\n' +
        '                    </thead>\n' +
        '                    <tbody>\n' +
        '                    <tr>\n' +
        '                        <th scope="row">State: x > 10mil</th>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> ....</td>\n' +
        '\n' +
        '\n' +
        '                    </tr>\n' +
        '                    <tr>\n' +
        '                        <th scope="row">State: 5mil< x <10mil</th>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> ....</td>\n' +
        '\n' +
        '                    </tr>\n' +
        '                    <tr>\n' +
        '                        <th scope="row">x <5mil</th>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> ....</td>\n' +
        '\n' +
        '                    </tr>\n' +
        '                    </tbody>\n' +
        '                </table>'
}

objective_node_1 = {
    parent: impact_on_asset_node_1,
    text: {name: "Objective"},
    innerHTML: '<table class="table  table-bordered">\n' +
        '                    <thead>\n' +
        '                    <tr>\n' +
        '                        <th scope="col" class="custom-table-header" colspan="5"> Objective Node</th>\n' +
        '\n' +
        '                    </tr>\n' +
        '                    <tr>\n' +
        '                        <th scope="col" class="custom-table-header"> Asset:Consequence</th>\n' +
        '                        <th scope="col" class="custom-table-header" colspan="3"> IT Department Equipment: Modify data\n' +
        '                        </th>\n' +
        '                        <th scope="col" class="custom-table-header"> ....\n' +
        '                        </th>\n' +
        '                    </tr>\n' +
        '                    </thead>\n' +
        '                    <thead class="thead-light">\n' +
        '                    <tr>\n' +
        '                        <th scope="col" class="custom-table-header"> Impact</th>\n' +
        '                        <th scope="col" class="custom-table-header" colspan="3"> Defective</th>\n' +
        '                        <th scope="col" class="custom-table-header"> ....</th>\n' +
        '                    </tr>\n' +
        '                    </thead>\n' +
        '                    <thead class="thead-light">\n' +
        '                    <tr>\n' +
        '                        <th scope="col" class="custom-table-header"> State</th>\n' +
        '                        <th scope="col" class="custom-table-header"> In use</th>\n' +
        '                        <th scope="col" class="custom-table-header"> Online</th>\n' +
        '                        <th scope="col" class="custom-table-header"> Offline</th>\n' +
        '                        <th scope="col" class="custom-table-header"> ...</th>\n' +
        '\n' +
        '                    </tr>\n' +
        '                    </thead>\n' +
        '                    <tbody>\n' +
        '                    <tr>\n' +
        '                        <th scope="row">State: x > 10mil</th>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> ....</td>\n' +
        '\n' +
        '\n' +
        '                    </tr>\n' +
        '                    <tr>\n' +
        '                        <th scope="row">State: 5mil< x <10mil</th>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> ....</td>\n' +
        '\n' +
        '                    </tr>\n' +
        '                    <tr>\n' +
        '                        <th scope="row">x <5mil</th>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> yy%</td>\n' +
        '                        <td> xx%</td>\n' +
        '                        <td> ....</td>\n' +
        '\n' +
        '                    </tr>\n' +
        '                    </tbody>\n' +
        '                </table>'
}

simple_chart_config = [
    config, threat_exposure_node, pre_incident_response_node, incident_materialisation_node, post_incident_response_node,
    consequence_node, impact_on_asset_node, impact_on_asset_node_1, objective_node, objective_node_1
];

// simple_chart_config = {
//     chart: {
//         container: "#tree-simple",
//
//     },
//     nodeStructure: {
//         innerHTML: '<div class="card bg-light mb-3 custom-dashboard-single-asset-card" style="max-width: 18rem;">\n' +
//             '                <div class="card-header"> Threat XXXX</div>\n' +
//             '                <div class="card-body">\n' +
//             '                    <h5 class="card-title">Consequences</h5>\n' +
//             '                    <p class="card-text"> Lorem Ipsum --- </p>\n' +
//             '                    <h5 class="card-title"> Typical Severity</h5>\n' +
//             '                    <p class="card-text"> Lorem Ipsum --- </p>\n' +
//             '                </div>\n' +
//             '            </div>',
//         children: [
//             {
//                 innerHTML : '<div class="card bg-light mb-3 custom-card-tree" style="max-width: 18rem;">\n' +
//                     '                    <div class="card-header">Gain Privileges</div>\n' +
//                     '                    <div class="card-body">\n' +
//                     '                        <h5 class="card-title">Scope</h5>\n' +
//                     '                        <p class="card-text">Confidentiality </p>\n' +
//                     '                        <p class="card-text"> Integrity </p>\n' +
//                     '                        <p class="card-text"> Authentication </p>\n' +
//                     '                        <p class="card-text"> Access Control </p>\n' +
//                     '                        <a href="#" class="card-link"> Remove</a>\n' +
//                     '                        <a href="#" class="card-link"> Edit</a>\n' +
//                     '                    </div>\n' +
//                     '                </div>'
//             },
//             {
//                 text: { name: "Second child" }
//             }
//         ]
//     }
// };


var my_chart = new Treant(simple_chart_config);

