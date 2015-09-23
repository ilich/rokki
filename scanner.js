"use strict";

var path = require("path"),
    fs = require("fs"),
    util = require("util"),
    signatures = require("./signatures");

var TEST = {
    RE: 0,
    PATH: 1
};

function Scanner(options) {
    this.options = options || {
        maxSize: null,
        include: null,
        exclude: null
    };
}

Scanner.prototype.scan = function (file, callback) {
    if (!util.isFunction(callback)) {
        callback = function (path, infected, data) {
        }; 
    }
    
    var filename = path.basename(file).toLowerCase();
    
    // Verify include/exclude filename rules
    if (util.isRegExp(this.options.exclude) && this.options.exclude.test(filename)) {
        return callback(file, null, "Excluded");
    }
    
    if (util.isRegExp(this.options.include) && !this.options.include.test(filename)) {
        return callback(file, null, "Excluded");
    }
    
    var self = this;
    
    // Verify that file exists and it is less then the maximum allowed size
    fs.exists(file, function (exists) {
        if (!exists) {
            return callback(file, null, "File is not found");
        }
        
        fs.stat(file, function (err, stats) {
            if (err) {
                return callback(file, null, err);
            }
            
            if (util.isNumber(self.options.maxSize) &&  stats.size > self.options.maxSize) {
                return callback(file, null, "File is too big");
            }
            
            // Test malware filenames database
            if (signatures.db.path.indexOf(filename) > -1) {
                return callback(file, true, {
                    check: TEST.PATH,
                    malware: signatures.MALWARE_TYPE.WEB_SHELL,
                    impact: signatures.IMPACT_LEVEL.HIGH
                });
            }
            
            // Check file content
            fs.readFile(file, "utf8", function (err, data) {
                if (err) {
                    return callback(file, null, err);
                }
                
                for (var i = 0; i < signatures.db.re.length; i++) {
                    var signature = signatures.db.re[i];
                    if (signature.expr.test(data)) {
                        return callback(file, true, {
                            check: TEST.RE,
                            malware: signature.type,
                            impact: signature.impact,
                            id: signature.id
                        });
                    }
                }
                
                callback(file, false, null);    
            });            
        });
    });
};

module.exports = {
    TEST: TEST,
    Scanner: Scanner
};