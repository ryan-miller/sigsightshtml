function defaultChartLayout() {
    return {
        fontsize: 12,
        margin: {t: 0, b: 0, b:0}
    };
}

function defaultStackBarChartLayout() {
    def = defaultChartLayout();
    def.barmode = 'stack';
    return def;
}

function defaultGroupBarChartLayout() {
    def = defaultChartLayout();
    def.barmode = 'group';
    return def;
}

function defaultChartOptions() {
   return {responsive: true, displayModeBar: false};
}

function getUniqueTopSites(d) {
    var uniqueSites = [];

    for (row in d) {
        for (site in d[row].topSites) {
            var siteName = d[row].topSites[site].name;
            if (!uniqueSites.includes(siteName)) {
                uniqueSites.push(siteName);
            }
        }
    }

    return uniqueSites;
}

function isCveSignal(signal) {
    return (signal.substring(0,3) == 'CVE'); 
}

function isLoginOrRegistrationSignal(signal) {
    if (signal.substring(0,5) == 'LOGIN' || signal.substring(0,12) == 'REGISTRATION') {
        return true;
    }
    return false;
}

function isBadAnomalySignal(signal) {

    var badAnomalies = [
        'JSON-ERROR',
        'BODY-PARSER-EVASTION',
        'DOUBLEENCODING',
        'NOTUTF8',
        'XML-ERROR',
        'CODEINJECTION',
        'RESPONSESPLIT',
        'NULLBYTE',
        'MALFORMED-DATA',
        'ABNORMALPATH'
    ]

    return badAnomalies.includes(signal);

}

function showCorpSignalsBySiteChart(d) {

    var uniqueSites = getUniqueTopSites(d);

    var data = []

    for (uniqueSite in uniqueSites) {
        var x = [];
        var y = [];

        for (row in d) {
            for (site in d[row].topSites) {
                if (d[row].topSites[site].name == uniqueSites[uniqueSite]) {
                    x.push(d[row].name)
                    y.push(d[row].topSites[site].count)
                }
            }
        }
        data.push({'x': x, 'y': y, 'name': uniqueSites[uniqueSite], 'type': 'bar'});

    }

    Plotly.newPlot('corpSignalsBySite', data, defaultStackBarChartLayout(), defaultChartOptions());

}

function filterData(data, field, filter) {
    var filteredData = [];
    
    for (var row in data) {
        var fieldName = data[row][field];
        if (filter(fieldName)) {
            filteredData.push(data[row]);
        }
    }

    return filteredData;
}

function showLoginAndRegistrationBySite(d) {

    var filteredData = filterData(d, "name", isLoginOrRegistrationSignal);
    var uniqueSites = getUniqueTopSites(filteredData);
    var data = []

    for (var uniqueSite in uniqueSites) {
        var x = [];
        var y = [];

        for (row in filteredData) {
            for (site in filteredData[row].topSites) {
                if (filteredData[row].topSites[site].name == uniqueSites[uniqueSite]) {
                    x.push(filteredData[row].name)
                    y.push(filteredData[row].topSites[site].count)
                }
            }
        }
        data.push({'x': x, 'y': y, 'name': uniqueSites[uniqueSite], 'type': 'bar'});
    }

    Plotly.newPlot('loginAndRegistrationBySite', data, defaultStackBarChartLayout(), defaultChartOptions());

}

function showAnomalySignalsBySite(d) {

    var uniqueSites = getUniqueTopSites(d);
    var badAnomalyOnly = filterData(d, "name", isBadAnomalySignal);
    var data = []

    for (var uniqueSite in uniqueSites) {
        var x = [];
        var y = [];

        for (row in badAnomalyOnly) {
            for (site in badAnomalyOnly[row].topSites) {
                if (badAnomalyOnly[row].topSites[site].name == uniqueSites[uniqueSite]) {
                    x.push(badAnomalyOnly[row].name)
                    y.push(badAnomalyOnly[row].topSites[site].count)
                }
            }
        }
        data.push({'x': x, 'y': y, 'name': uniqueSites[uniqueSite], 'type': 'bar'});

    }

    Plotly.newPlot('anomalySignalsBySite', data, defaultStackBarChartLayout(), defaultChartOptions());

}

function showCveAnomalyBySiteChart(d) {

    var uniqueSites = getUniqueTopSites(d);
    var cveOnlyData = filterData(d, "name", isCveSignal);
    var data = []

    for (var uniqueSite in uniqueSites) {
        var x = [];
        var y = [];

        for (row in cveOnlyData) {
            for (site in cveOnlyData[row].topSites) {
                if (cveOnlyData[row].topSites[site].name == uniqueSites[uniqueSite]) {
                    x.push(cveOnlyData[row].name)
                    y.push(cveOnlyData[row].topSites[site].count)
                }
            }
        }
        data.push({'x': x, 'y': y, 'name': uniqueSites[uniqueSite], 'type': 'bar'});

    }

    Plotly.newPlot('cveAnomalyBySite', data, defaultStackBarChartLayout(), defaultChartOptions());

}

function showTopAttackSignalsBySite(d) {

    var uniqueSites = getUniqueTopSites(d);
    var data = []

    for (uniqueSite in uniqueSites) {
        var x = [];
        var y = [];
        for (row in d) {

            for (site in d[row].topSites) {
                if (d[row].topSites[site].name == uniqueSites[uniqueSite]) {
                    x.push(d[row].name)
                    y.push(d[row].topSites[site].count)
                } 
            }

        }
        data.push({'x': x, 'y': y, 'name': uniqueSites[uniqueSite], 'type': 'bar'});
    }
      
    Plotly.newPlot('topAttackSignalsBySite', data, defaultStackBarChartLayout(), defaultChartOptions());

}

function showTopFourBlockedChart(d) {

    var blocked = {
        x: [],
        y: [],
        name: 'Blocked',
        type: 'bar'
    }

    var attack = {
        x: [],
        y: [],
        name: 'Attack',
        type: 'bar'
    }

    var flagged = {
        x: [],
        y: [],
        name: 'Flagged',
        type: 'bar'
    }

    for (var row in d) {
        blocked['x'].push(d[row].name);
        blocked['y'].push(d[row].blockedCount); 

        attack['x'].push(d[row].name);
        attack['y'].push(d[row].attackCount);

        flagged['x'].push(d[row].name);
        flagged['y'].push(d[row].flaggedCount);
    }

    var data = [blocked, attack, flagged];

    Plotly.newPlot('topFourSitesByBlockedRequests', data, defaultGroupBarChartLayout(), defaultChartOptions());

}

function sortAndChop(d, n, p) {

    d.sort((b, a) => a[p] - b[p]);
    choppedData = []
    var counter = 0;
    if (n > d.length){
        n = d.length;
    }
    while (counter < n) {
        choppedData.push(d[counter]);
        counter = counter + 1;
    }
    return choppedData;
}

function attackChartDataPrep(d) {

    var v = []
    var l = []

    for (var row in d) {
        v.push(d[row].requestCount)
        l.push(d[row].countryName)
    }

    return {values: v, labels: l}

}

function compressAttackData(d) {
    var compressedAttackData = []
    var site
    var siteRow
    var country
    var attackRow
    var attackObject

    for (site in d) {
        siteRow = d[site];
        for (country in siteRow.topAttackSources) {
            
            attackRow = siteRow.topAttackSources[country];

            updateRequestCount(compressedAttackData, {
                "countryCode": attackRow.countryCode,
                "countryName": attackRow.countryName,
                "requestCount": attackRow.requestCount,
                "y": attackRow.requestCount
            });
        }
    }

    // sort attack data by request Count descending
    compressedAttackData.sort((b, a) => a.requestCount - b.requestCount);
    return compressedAttackData;
}

function updateRequestCount(attacks, countryObj) {
    var country
    var countryExists = false;
    for (country in attacks) {
        if (attacks[country].countryCode == countryObj.countryCode) {
            countryExists = true;
            attacks[country].requestCount += countryObj.requestCount;
            attacks[country].y += countryObj.requestCount;
        } 
    }
    if (countryExists == false) {
        attacks.push({
            "countryCode": countryObj.countryCode,
            "requestCount": countryObj.requestCount,
            "countryName": countryObj.countryName,
            "y": countryObj.requestCount
        });
    }
}

function countryExists(attacks, countryObj) {
    var country
    for (country in attacks) {
        if (attacks[country].countryCode == countryObj.countryCode) {
            return true;
        }
    }
    return false;
}