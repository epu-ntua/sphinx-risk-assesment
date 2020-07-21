$(document).ready(function () {
            $('#asset-table-1').DataTable();

            $("#dashboard_tab_content_1").toggle();
            $("#dashboard_tab_content_2").toggle();
            $("#dashboard_tab_content_3").toggle();
            $("#dashboard_tab_content_4").toggle();
            $("#dashboard_tab_content_5").toggle();

        });

        function toggleTab(tabNumber) {
            const tabToToggle = "#dashboard_tab_" + tabNumber.toString();
            const iconToToggle = "#dashboard_tab_icon_" + tabNumber.toString();
            const tabContentToToggle = "#dashboard_tab_content_" + tabNumber.toString();

            console.log("Hey");
            console.log(tabNumber.toString());

            $(tabToToggle).toggleClass("general-dashboard-tab-active");
            $(iconToToggle).toggleClass("general-dashboard-tab-icon-selected");
            $(iconToToggle).toggleClass("fa-toggle-right");
            $(iconToToggle).toggleClass("fa-toggle-down");
            $(tabContentToToggle).toggle();
        }

