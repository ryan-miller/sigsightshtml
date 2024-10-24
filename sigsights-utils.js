function defaultChartLayout() {
    return {
        font: { size: 12 }, // Use 'font' for font size
        margin: { t: 0, b: 0 } // Fixed duplicate 'b' property
    };
}

function defaultStackBarChartLayout() {
    const layout = defaultChartLayout(); // Use const for better scoping
    layout.barmode = 'stack'; // Set bar mode to stack
    return layout;
}

function defaultGroupBarChartLayout() {
    const layout = defaultChartLayout();
    layout.barmode = 'group';
    return layout;
}

function defaultChartOptions() {
   return {
        responsive: true, 
        displayModeBar: false
    };
}

function getUniqueTopSites(data) {
    const uniqueSites = new Set(); // Use Set for unique values

    for (const row of data) {
        for (const site of row.topSites) {
            uniqueSites.add(site.name); // Add site name to Set
        }
    }

    return Array.from(uniqueSites); // Convert Set back to array
}

function isCveSignal(signal) {
    return signal.startsWith('CVE');
}

function isLoginOrRegistrationSignal(signal) {
    return signal.startsWith('LOGIN') || signal.startsWith('REGISTRATION');
}

function isBadAnomalySignal(signal) {
    const badAnomalies = new Set([
        'JSON-ERROR',
        'BODY-PARSER-EVASION',
        'DOUBLEENCODING',
        'NOTUTF8',
        'XML-ERROR',
        'CODEINJECTION',
        'RESPONSESPLIT',
        'NULLBYTE',
        'MALFORMED-DATA',
        'ABNORMALPATH'
    ]);

    return badAnomalies.has(signal);
}

function showCorpSignalsBySiteChart(d) {
    const uniqueSites = getUniqueTopSites(d);
    const data = [];

    uniqueSites.forEach(siteName => {
        const x = [];
        const y = [];

        d.forEach(row => {
            row.topSites.forEach(site => {
                if (site.name === siteName) {
                    x.push(row.name);
                    y.push(site.count);
                }
            });
        });

        data.push({ x, y, name: siteName, type: 'bar' });
    });

    Plotly.newPlot('corpSignalsBySite', data, defaultStackBarChartLayout(), defaultChartOptions());
}

function filterData(data, field, filter) {
    return data.filter(row => filter(row[field]));
}

function showSignalsBySite(d, signalCheckFunction, plotElementId) {
    const filteredData = filterData(d, "name", signalCheckFunction);
    const uniqueSites = getUniqueTopSites(filteredData);
    const data = [];

    uniqueSites.forEach(siteName => {
        const x = [];
        const y = [];

        filteredData.forEach(row => {
            row.topSites.forEach(site => {
                if (site.name === siteName) {
                    x.push(row.name);
                    y.push(site.count);
                }
            });
        });

        data.push({ x, y, name: siteName, type: 'bar' });
    });

    Plotly.newPlot(plotElementId, data, defaultStackBarChartLayout(), defaultChartOptions());
}

function showLoginAndRegistrationBySite(d) {
    showSignalsBySite(d, isLoginOrRegistrationSignal, 'loginAndRegistrationBySite');
}

function showAnomalySignalsBySite(d) {
    showSignalsBySite(d, isBadAnomalySignal, 'anomalySignalsBySite');
}

function showCveAnomalyBySiteChart(d) {
    showSignalsBySite(d, isCveSignal, 'cveAnomalyBySite');
}

function showTopSignalsBySite(d, plotElementId) {
    const uniqueSites = getUniqueTopSites(d);
    const data = [];

    uniqueSites.forEach(siteName => {
        const x = [];
        const y = [];

        d.forEach(row => {
            row.topSites.forEach(site => {
                if (site.name === siteName) {
                    x.push(row.name);
                    y.push(site.count);
                }
            });
        });

        data.push({ x, y, name: siteName, type: 'bar' });
    });

    Plotly.newPlot(plotElementId, data, defaultStackBarChartLayout(), defaultChartOptions());
}

function showTopAttackSignalsBySite(d) {
    showTopSignalsBySite(d, 'topAttackSignalsBySite');
}

function showTopFourBlockedChart(d) {
    const data = [
        { x: [], y: [], name: 'Blocked', type: 'bar' },
        { x: [], y: [], name: 'Attack', type: 'bar' },
        { x: [], y: [], name: 'Flagged', type: 'bar' }
    ];

    d.forEach(row => {
        data[0].x.push(row.name);
        data[0].y.push(row.blockedCount);
        data[1].x.push(row.name);
        data[1].y.push(row.attackCount);
        data[2].x.push(row.name);
        data[2].y.push(row.flaggedCount);
    });

    Plotly.newPlot('topFourSitesByBlockedRequests', data, defaultGroupBarChartLayout(), defaultChartOptions());
}

function sortAndChop(d, n, p) {
    // Sort the data array based on the specified property in descending order
    d.sort((a, b) => b[p] - a[p]);

    // Slice the sorted array to get the top n elements
    return d.slice(0, Math.min(n, d.length));
}

function attackChartDataPrep(data) {
    const values = data.map(row => row.requestCount);
    const labels = data.map(row => row.countryName);

    return { values, labels };
}

function compressAttackData(data) {
    const compressedAttackData = [];

    for (const siteRow of data) {
        for (const attackRow of siteRow.topAttackSources) {
            updateRequestCount(compressedAttackData, {
                countryCode: attackRow.countryCode,
                countryName: attackRow.countryName,
                requestCount: attackRow.requestCount,
                y: attackRow.requestCount
            });
        }
    }

    // Sort attack data by request count in descending order
    compressedAttackData.sort((a, b) => b.requestCount - a.requestCount);
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

function updateRequestCount(attacks, countryObj) {
    const existingCountry = attacks.find(country => country.countryCode === countryObj.countryCode);

    if (existingCountry) {
        // Update existing country's request count
        existingCountry.requestCount += countryObj.requestCount;
        existingCountry.y += countryObj.requestCount;
    } else {
        // Add new country entry
        attacks.push({
            countryCode: countryObj.countryCode,
            requestCount: countryObj.requestCount,
            countryName: countryObj.countryName,
            y: countryObj.requestCount
        });
    }
}

function countryExists(attacks, countryObj) {
    return attacks.some(country => country.countryCode === countryObj.countryCode);
}