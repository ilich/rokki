"use strict";

var util = require("util"),
    crypto = require("crypto"),
    fs = require("fs"),
    path = require("path"),
    sqlite3 = require("sqlite3");

function Whitelist(dbFilename, logger) {
    if (!util.isString(dbFilename) || dbFilename.lenght === 0) {
        dbFilename = ":memory:";
    }

    var self = this;    
    self.db = new sqlite3.Database(dbFilename);
    
    // Create Whitelist tables if needed
    self.db.on("open", function () {
       self.db.serialize(function () {
           self.db.run("create table if not exists Whitelist(checksum text, filename text, product text)");
       });
    });
    
    // SQLite error handler - notify rokki
    self.db.on("error", function (err) {
        if (!logger) {
            return;
        }
        
        logger.error(err);
        process.exit(1);
    });
    
    process.on("exit", function () {
        // Make sure we close the database before exit.
        if (self.db) {
            self.db.close();
        }
    });
}

Whitelist.prototype.checksum = function (file, callback) {
    if (!util.isFunction(callback)) {
        throw new Error("Callback has not been provided");
    }
    
    fs.exists(file, function (exists) {
        if (!exists) {
            if (util.isFunction(callback)) {
                callback(file + " is not found", null);
            }
            
            return;
        }
        
        var hash = crypto.createHash("sha1");
        var stream = fs.createReadStream(file);
        
        stream.on("data", function (data) {
            hash.update(data); 
        });
        
        stream.on("end", function () {
            var sha1 = hash.digest("hex");
            callback(null, sha1);
        });
    });
};

Whitelist.prototype.update = function (folder, product, callback) {
    var self = this;
    
    fs.stat(folder, function (err, stats) {
        if (err !== null) {
            return callback(err, null, null);
        }
        
        if (stats.isFile()) {
            self.updateFile(folder, callback);
        } else {
            fs.readdir(folder, function (err, files) {
                if (err) {
                    return callback(err, null, null);
                }
                
                for (var i = 0; i < files.length; i++) {
                    var target = path.join(folder, files[i]);
                    var fileInfo = fs.statSync(target);
                    
                    if (fileInfo.isDirectory()) {
                        self.update(target, product, callback);
                    } else if (fileInfo.isFile()) {
                        self.updateFile(target, product, callback);
                    }
                }    
            });            
        }
    });  
};

Whitelist.prototype.updateFile = function (filename, product, callback) {
    if (!util.isFunction(callback)) {
        throw new Error("Callback has not been provided");
    }
    
    var self = this;
    
    self.db.serialize(function () {
        self.checksum(filename, function (err, sha1) {
            if (err) {
                callback(err, null, null);
            } else {
                self.db.run(
                    "insert into Whitelist (checksum, filename, product) values(?, ?, ?)"
                    , [ sha1, filename, product ]
                    , function (err) {
                        if (err) {
                            callback(err, null, null);
                        } else {
                            callback(null, filename, sha1);
                        }
                    }
                );
            }
        });     
    });
};

Whitelist.prototype.isInWhitelist = function (checksum, callback) {
    if (!util.isFunction(callback)) {
        throw new Error("Callback has not been provided");
    }
    
    var self = this;
    
    self.db.serialize(function () {
        self.db.get("select filename, product from Whitelist where checksum = ?", checksum, function (err, row) {
            if (err) {
                return callback(err, null, null);    
            }
            
            if (typeof row === "undefined") {
                callback(false, null, null);
            } else {
                callback(true, row.filename, row.product);
            }
        });
    });
};

Whitelist.prototype.isFileInWhitelist = function (file, callback) {
    if (!util.isFunction(callback)) {
        throw new Error("Callback has not been provided");
    }
    
    var self = this;
    self.checksum(file, function (err, sha1) {
        if (err) {
            return callback(err, null, null);    
        }
        
        self.isInWhitelist(sha1, function (result, filename, product) {
            if (err) {
                callback(err, null, null);    
            } else {
                callback(result, filename, product);
            }
        });
    });
};

module.exports = Whitelist;