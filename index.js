#!/usr/bin/env node

"use strict";

var util = require("util"),
    fs = require("fs"),
    winston = require("winston"),
    signatures = require("./signatures"),
    scanner = require("./scanner"),
    Whitelist = require("./whitelist"),
    commander = require("commander"),
    program = new commander.Command("rokki");
    
var tool = (function() {
    
    function main() {
        program
            .version("0.1.0")
            .description("Simple web-sites malware scanner.")
            .usage("[options] [file/directory]")
            .option("-v, --verbose", "be verbose.")
            .option("-r, --recursive", "scan directories recursively. All the subdirectories in the given directory will be scanned.")
            .option("-l, --log <file>", "save scan report to #file.")
            .option("--json", "save scan report in JSON format.")
            .option("--exclude <regex>", "don't scan file names matching regular expression.")
            .option("--exclude-dir <regex>", "don't scan directory names matching regular expression.")
            .option("--include <regex>", "only scan file matching regular expression.")
            .option("--include-dir <regex>", "only scan directory matching regular expression.")
            .option("--max-filesize <n>", "scan files with size at most #n kilobytes (default: 100 MB)", 102400)
            .option("--update-whitelist", "add files signatures to the whitelist database provided by --whitelist parameter")
            .option("-w, --whitelist <file>", "use whitelist database to minimize false positive results", "")
            .option("-p, --product <name>", "provide product information added to the whitelist database", "");
        
        program.on("--help", function () {
            console.log("EXAMPLES:\n"); 
            console.log("Check all files in /var/www/htdocs folder\n");
            console.log("    $ rokki -r /var/www/htdocs\n");
            console.log("Check only JavaScript in /var/www/htdocs folder and show the list of all checked files\n");
            console.log("    $ rokki -r -v --include \\.js$ /var/www/htdocs");
            console.log("Add wordpress to whitelist\n");
            console.log("    $ rokki --update-whitelist -w ./whitelist.sqlite -p \"WordPress 4.3.1\" ./temp/wordpress");
            console.log("Check all files in /var/www/htdocs folder using whitelist\n");
            console.log("    $ rokki -r -w ./whitelist.sqlite /var/www/htdocs\n");
        });
        
        program.parse(process.argv);
        
        if (program.updateWhitelist) {
            updateWhitelist();
        } else {
            scan();
        }        
    }
    
    function scan() {
        var options = configureScanner();
        var logger = configureLogger();
        var target = getTarget();
        
        var scan = new scanner.Scanner(options);
        scan.scanFolder(target, function (file, infected, data) {
            var msg;
            
            if (infected === null) {
                if (util.isString(file) && file.length > 0) {
                    msg = util.format("%s - %s", file, data);    
                } else {
                    msg = data;
                }
                
                logger.log("error", msg);
            }
            else if (infected === false) {
                logger.log("verbose", file + " - OK");
            } else if (infected === "Whitelist") {
                logger.log("verbose", file + " - Whitelist");
            } else {
                var level, malware = "";
                
                switch (data.impact) {
                    case signatures.IMPACT_LEVEL.HIGH:
                        level = "error";
                        break;
                        
                    case signatures.IMPACT_LEVEL.MEDIUM:
                        level = "warn";
                        break;
                    
                    default:
                        level = "info";
                        break;
                }
                
                switch (data.malware) {
                    case signatures.MALWARE_TYPE.WEB_SHELL:
                        malware = "Web Shell";
                        break;
                        
                    case signatures.MALWARE_TYPE.VIRUS:
                        malware = "Virus";
                        break;
                        
                    case signatures.MALWARE_TYPE.MALICIOUS_CODE:
                        malware = "Malicious Code";
                        break;
                }
                
                if (data.check === scanner.TEST.PATH) {
                    msg = util.format("%s - %s (filename)", file, malware);
                } else {
                    msg = util.format("%s - %s, ID: %d (regular expression: %s)", file, malware, data.id, data.regex);
                }
                
                logger.log(level, msg);
            }
        });
    }
    
    function updateWhitelist() {
        var logger = configureLogger();
        var db = program.whitelist;
        var product = program.product;
        var target = getTarget();
        
        if (!util.isString(db) || db.length === 0) {
            logger.error("whitelist database file is required");
            return;
        }
        
        var whitelist = new Whitelist(db);
        whitelist.update(target, product, function (err, file, sha1) {
            if (err === null) {
                logger.info(file + " - " + sha1);
            } else {
                logger.error(err);
            }
        });
    }
    
    function getTarget() {
        return program.args.length === 0 ? "./" : program.args[0];
    }
    
    function configureScanner() {
        var maxSize = parseInt(program.maxFilesize) * 1024;
        
        var options = {
            maxSize: maxSize === 0 ? 104857600 : maxSize,
            include: util.isString(program.include) ? new RegExp(program.include, "ig") : null,
            exclude: util.isString(program.exclude) ? new RegExp(program.exclude, "ig") : null,
            recursive: program.recursive === true,
            includeFolders: util.isString(program.includeDir) ? new RegExp(program.includeDir, "ig") : null,
            excludeFolders: util.isString(program.excludeDir) ? new RegExp(program.excludeDir, "ig") : null,
            whitelist: program.whitelist
        };
        
        return options;        
    }
    
    function configureLogger() {
        var level = program.verbose === true ? "verbose" : "info";
        
        var logger = new winston.Logger({
            transports: [
                new winston.transports.Console({
                    level: level,
                    handleExceptions: true,
                    json: false,
                    colorize: true                    
                })
            ]            
        });
        
        if (!util.isString(program.log)) {
            return logger;
        }
        
        logger.add(winston.transports.File, {
            level: level,
            filename: program.log,
            handleExceptions: true,
            json: program.json === true
        });
                
        return logger;
    }
    
    return {
        start: main
    };
    
})();

if (require.main === module) {
    tool.start();    
} else {
    module.exports = {
        Scanner: scanner.Scanner,
        TEST: scanner.TEST,
        IMPACT_LEVEL: signatures.IMPACT_LEVEL,
        MALWARE_TYPE: signatures.MALWARE_TYPE
    };
}