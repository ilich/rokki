"use strict";

var signatures = require("./signatures"),
    scanner = require("./scanner");

function main() {
    // TODO
}

if (require.main === module) {
    main();    
} else {
    module.exports = {
        Scanner: scanner.Scanner,
        TEST: scanner.TEST,
        IMPACT_LEVEL: signatures.IMPACT_LEVEL,
        MALWARE_TYPE: signatures.MALWARE_TYPE
    };
}