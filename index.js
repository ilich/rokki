#!/usr/bin/env node

"use strict";

var util = require("util"),
    fs = require("fs"),
    winston = require("winston"),
    signatures = require("./signatures"),
    scanner = require("./scanner"),
    program = require("commander");
    
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
            .parse(process.argv);
            
        var options = configureScanner();
        var logger = configureLogger();
        var target = getTarget();
        
        var scan = new scanner.Scanner(options);
        scan.scanFolder(target, function (file, infected, data) {
            if (infected === null) {
                logger.log("error", data);
            }
            else if (infected === false) {
                logger.log("verbose", file + " - OK");
            } else {
                var level, malware = "", msg;
                
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