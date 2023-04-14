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
            attackObject = {
                "countryCode": attackRow.countryCode,
                "countryName": attackRow.countryName,
                "requestCount": attackRow.requestCount,
                "y": attackRow.requestCount
            };

            if (countryExists(compressedAttackData, attackObject)) {
                updateRequestCount(compressedAttackData, attackObject);
            } else {
                compressedAttackData.push(attackObject);
            }
        }
    }

    // sort attack data by request Count descending
    compressedAttackData.sort((b, a) => a.requestCount - b.requestCount);
    return compressedAttackData;
}

function updateRequestCount(attacks, countryObj) {
    var country
    for (country in attacks) {
        if (attacks[country].countryCode == countryObj.countryCode) {
            attacks[country].requestCount += countryObj.requestCount;
            attacks[country].y += countryObj.requestCount;
        }
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


