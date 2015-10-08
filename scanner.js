"use strict";

var path = require("path"),
    fs = require("fs"),
    util = require("util"),
    signatures = require("./signatures"),
    Whitelist = require("./whitelist");

var TEST = {
    RE: 0,
    PATH: 1
};

function Scanner(options) {
    this.options = options || {
        maxSize: 104857600,     // 100 MB
        include: null,
        exclude: null,
        recursive: false,
        includeFolders: null,
        excludeFolders: null,
        whitelist: null
    };
    
    if (util.isString(this.options.whitelist) && this.options.whitelist.length > 0) {
        this.whitelist = new Whitelist(this.options.whitelist);
    } else {
        this.whitelist = null;
    }
}

Scanner.prototype.scan = function (file, callback) {
    if (!util.isFunction(callback)) {
        throw new Error("Callback has not been provided");
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
            
            if (!stats.isFile()) {
                return callback(file, null, "File should be provided");
            }
            
            if (util.isNumber(self.options.maxSize) &&  stats.size > self.options.maxSize) {
                return callback(file, null, "File is too big");
            }
            
            // Test malware filenames database
            if (signatures.db.path.indexOf(filename) > -1) {
                if (self.whitelist === null) {
                    return callback(file, true, {
                        check: TEST.PATH,
                        malware: signatures.MALWARE_TYPE.WEB_SHELL,
                        impact: signatures.IMPACT_LEVEL.HIGH
                    });    
                } else {
                    // Check is file is in the whitelist
                    self.whitelist.isFileInWhitelist(file, function (result, filename, product) {
                        if (util.isBoolean(result)) {
                            if (result) {
                                callback(file, "Whitelist", null); 
                            } else {
                                callback(file, true, {
                                    check: TEST.PATH,
                                    malware: signatures.MALWARE_TYPE.WEB_SHELL,
                                    impact: signatures.IMPACT_LEVEL.HIGH
                                });
                            }
                        } else {
                            callback(file, null, result);
                        }    
                    });
                }
                
            }
            
            // Check file content
            var processFile = function (err, data) {
                if (err) {
                    if (err.code === "EMFILE") {
                        // Too many files open. Try to reread the file in a second.
                        setTimeout(function () {
                           fs.readFile(file, "utf8", processFile); 
                        }, 1000);
                    } else {
                        return callback(file, null, err);    
                    }
                }
                
                for (var i = 0; i < signatures.db.re.length; i++) {
                    var signature = signatures.db.re[i];
                    if (signature.expr.test(data)) {
                        if (self.whitelist === null) {
                            return callback(file, true, {
                                check: TEST.RE,
                                malware: signature.type,
                                impact: signature.impact,
                                id: signature.id,
                                regex: signature.expr
                            });
                        } else {
                             // Check is file is in the whitelist
                            self.whitelist.isFileInWhitelist(file, function (result, filename, product) {
                                if (util.isBoolean(result)) {
                                    if (result) {
                                        callback(file, "Whitelist", null); 
                                    } else {
                                        callback(file, true, {
                                            check: TEST.RE,
                                            malware: signature.type,
                                            impact: signature.impact,
                                            id: signature.id,
                                            regex: signature.expr
                                        });
                                    }
                                } else {
                                    callback(file, null, result);
                                }    
                            });
                        }
                    }
                }
                
                callback(file, false, null); 
            };
            
            fs.readFile(file, "utf8", processFile);            
        });
    });
};

Scanner.prototype.scanFolder = function (folder, callback) {
    if (!util.isFunction(callback)) {
        throw new Error("Callback has not been provided");
    }
    
    var self = this;
    
    fs.exists(folder, function (exists) {
        if (!exists) {
            return callback(folder, null, "Folder is not found");
        }
        
        fs.stat(folder, function (err, stats) {
            if (!stats.isDirectory()) {
                return self.scan(folder, callback);
            }
            
            // Verify include/exclude folders
            folder = fs.realpathSync(folder);
            var name = path.basename(folder);
            
            if (util.isRegExp(self.options.excludeFolders) && self.options.excludeFolders.test(name)) {
                return callback(folder, null, "Excluded folder");
            }
            
            if (util.isRegExp(self.options.includeFolders) && !self.options.includeFolders.test(name)) {
                return callback(folder, null, "Excluded folder");
            }
            
            fs.readdir(folder, function (err, files) {
                if (err) {
                    return callback(folder, null, err);
                }
                
                for (var i = 0; i < files.length; i++) {
                    var target = path.join(folder, files[i]);
                    var fileInfo = fs.statSync(target);
                    
                    if (fileInfo.isDirectory() && self.options.recursive) {
                        self.scanFolder(target, callback);
                    } else if (fileInfo.isFile()) {
                        self.scan(target, callback);
                    }
                }
            }); 
        });
    });
};

module.exports = {
    TEST: TEST,
    Scanner: Scanner
};