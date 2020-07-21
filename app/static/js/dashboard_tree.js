simple_chart_config = {
    chart: {
        container: "#tree-simple"
    },

    nodeStructure: {
        innerHTML: '<div class="card bg-light mb-3 custom-dashboard-single-asset-card" style="max-width: 18rem;">\n' +
            '                <div class="card-header"> Threat XXXX</div>\n' +
            '                <div class="card-body">\n' +
            '                    <h4 class="card-title">Consequences</h4>\n' +
            '                    <p class="card-text"> Lorem Ipsum --- </p>\n' +
            '                    <h4 class="card-title"> Typical Severity</h4>\n' +
            '                    <p class="card-text"> Lorem Ipsum --- </p>\n' +
            '                </div>\n' +
            '            </div>',
        children: [
            {
                innerHTML : '<div class="card bg-light mb-3 custom-card-tree" style="max-width: 18rem;">\n' +
                    '                    <div class="card-header">Gain Privileges</div>\n' +
                    '                    <div class="card-body">\n' +
                    '                        <h4 class="card-title">Scope</h4>\n' +
                    '                        <p class="card-text">Confidentiality </p>\n' +
                    '                        <p class="card-text"> Integrity </p>\n' +
                    '                        <p class="card-text"> Authentication </p>\n' +
                    '                        <p class="card-text"> Access Control </p>\n' +
                    '                        <a href="#" class="card-link"> Remove</a>\n' +
                    '                        <a href="#" class="card-link"> Edit</a>\n' +
                    '                    </div>\n' +
                    '                </div>'
            },
            {
                text: { name: "Second child" }
            }
        ]
    }
};


var my_chart = new Treant(simple_chart_config);