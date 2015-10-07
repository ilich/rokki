"use strict";

var util = require("util"),
    crypto = require("crypto"),
    fs = require("fs"),
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
            if (util.isFunction(callback)) {
                callback(null, sha1);
            }
        });
    });
};

Whitelist.prototype.update = function (path, product, callback) {
    if (!util.isFunction(callback)) {
        throw new Error("Callback has not been provided");
    }
    
    var self = this;
    
    fs.stat(path, function (err, stats) {
        if (stats.isFile()) {
            self.updateFile(path, callback);
        } else {
            // TODO
        }
    });  
};

Whitelist.prototype.updateFile = function (path, product, callback) {
    if (!util.isFunction(callback)) {
        throw new Error("Callback has not been provided");
    }
    
    var self = this;
    
    self.db.serialize(function () {
        self.checksum(path, function (err, sha1) {
            if (err) {
                callback(err, null, null);
            } else {
                self.db.run(
                    "insert into Whitelist (checksum, filename, product) values(?, ?, ?)"
                    , [ sha1, path, product ]
                    , function (err) {
                        if (err) {
                            callback(err, null, null);
                        } else {
                            callback(null, path, sha1);
                        }
                    });
            }
        });     
    });
}

module.exports = Whitelist;