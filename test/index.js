"use strict";

var assert = require("assert"),
    path = require("path"),
    rokki = require(".."),
    Whitelist = require("../whitelist");

var testFolder = path.join(__dirname, "data");

describe("Malware Scanner", function () {
    
    function checkErrorMessage(msg) {
        return function (expectedFile, file, infected, data) {
            assert.strictEqual(file, expectedFile);
            assert.strictEqual(infected, null);
            assert.strictEqual(data, msg);
        }
    }
    
    var notFound = checkErrorMessage("File is not found"),
        folderNotFound = checkErrorMessage("Folder is not found"),
        useFolderInstedOfFile = checkErrorMessage("File should be provided"),
        excluded = checkErrorMessage("Excluded"),
        tooBig = checkErrorMessage("File is too big");
    
    function malware(expectedFile, file, infected, data) {
        assert.strictEqual(file, expectedFile);
        assert.strictEqual(infected, true);
        assert.strictEqual(data.malware, rokki.MALWARE_TYPE.WEB_SHELL);
        assert.strictEqual(data.impact, rokki.IMPACT_LEVEL.HIGH);
    }
    
    function cleanFile(expectedFile, file, infected, data) {
        assert.strictEqual(file, expectedFile);
        assert.strictEqual(infected, false);
        assert.strictEqual(data, null);
    }
    
    function scanFolder(scanner, folder, expectedMalware, done) {
        scanner.scanFolder(folder, function (file, infected, data) {
            if (!infected) {
                return;
            }
            
            var idx = expectedMalware.indexOf(file);
            if (idx > -1) {
                expectedMalware.splice(idx, 1);
            }
            
            if (expectedMalware == 0) {
                done();
            }
        });
    }
    
    var scanner = new rokki.Scanner();
    
    it("try to scan folder with scan method", function (done) {
        scanner.scan(testFolder, function (file, infected, data) {
            useFolderInstedOfFile(testFolder, file, infected, data);
            done();
        });
    });
    
    it("try to scan missing file", function (done) {
        var target = path.join(testFolder, "missing.txt");
        
        scanner.scan(target, function (file, infected, data) {
            notFound(target, file, infected, data);
            done();
        });
    });
    
    it("exclude file - exclude pattern", function (done) {
        var scanner = new rokki.Scanner({
            include: /^[b|f|g]+/i,
            exclude: /^big/i,
        });
        
        var target = path.join(testFolder, "big.txt");
        
        scanner.scan(target, function (file, infected, data) {
            excluded(target, file, infected, data);
            done();
        });
    });
    
    it("exclude file - include pattern", function (done) {
        var scanner = new rokki.Scanner({
            include: /^[f|g]+/i,
        });
        
        var target = path.join(testFolder, "big.txt");
        
        scanner.scan(target, function (file, infected, data) {
            excluded(target, file, infected, data);
            done();
        });
    });
    
    it("exclude file - size", function (done) {
        var scanner = new rokki.Scanner({
            maxSize: 16000,
        });
        
        var target = path.join(testFolder, "big.txt");
        
        scanner.scan(target, function (file, infected, data) {
            tooBig(target, file, infected, data);
            done();
        });
    });
    
    it("file has not exceeded maximum size", function (done) {
        var scanner = new rokki.Scanner({
            maxSize: 16000,
        });
        
        var target = path.join(testFolder, "good.php");
        
        scanner.scan(target, function (file, infected, data) {
            cleanFile(target, file, infected, data);
            done();
        });
    });
    
    it("find malware by file name", function (done) {
        var target = path.join(testFolder, "fatal.php");
        
        scanner.scan(target, function (file, infected, data) {
            assert.strictEqual(data.check, rokki.TEST.PATH);
            malware(target, file, infected, data);
            done();
        });
    });
    
    it("find malware - ASP backdoor", function (done) {
        var target = path.join(testFolder, "bad.asp");
        
        scanner.scan(target, function (file, infected, data) {
            assert.strictEqual(data.id, 10);
            assert.strictEqual(data.check, rokki.TEST.RE);
            malware(target, file, infected, data);
            done();
        });
    });
    
    it("find malware - PHP backdoor", function (done) {
        var target = path.join(testFolder, "bad.php");
        
        scanner.scan(target, function (file, infected, data) {
            assert.strictEqual(data.id, 13);
            assert.strictEqual(data.check, rokki.TEST.RE);
            malware(target, file, infected, data);
            done();
        });
    });
    
    it("find malware - ASP clean", function (done) {
        var target = path.join(testFolder, "good.asp");
        
        scanner.scan(target, function (file, infected, data) {
            cleanFile(target, file, infected, data);
            done();
        });
    });
    
    it("find malware - PHP clean", function (done) {
        var target = path.join(testFolder, "good.php");
        
        scanner.scan(target, function (file, infected, data) {
            cleanFile(target, file, infected, data);
            done();
        });
    });
    
    it("scan missing folder", function (done) {
       var target = path.join(testFolder, "missing-folder");
       
       scanner.scanFolder(target, function (file, infected, data) {
            folderNotFound(target, file, infected, data);
            done();
        });
    });
    
    it("scan folder, but use file as a parameter", function (done) {
       var target = path.join(testFolder, "good.asp");
       
       scanner.scanFolder(target, function (file, infected, data) {
            cleanFile(target, file, infected, data);
            done();
        });
    });
    
    it("scan folder", function (done) {
       scanFolder(scanner, testFolder, [
           path.join(testFolder, "bad.asp"),
           path.join(testFolder, "bad.php"),
           path.join(testFolder, "fatal.php"),
       ], done);
    });
    
    it("scan folder recursively", function (done) {
        var scanner = new rokki.Scanner({ recursive: true });
        
        scanFolder(scanner, testFolder, [
            path.join(testFolder, "bad.asp"),
            path.join(testFolder, "bad.php"),
            path.join(testFolder, "fatal.php"),
            path.join(testFolder, "subfolder", "bad.cfm"),
        ], done);
    });
    
    it("exclude folder - exclude pattern", function (done) {
        var excludedFolder = path.join(testFolder, "excluded");
        
        var scanner = new rokki.Scanner({ 
            recursive: true,
            includeFolders: /[d|s|e]+/ig,
            excludeFolders: /excluded/ig 
        });
        
        scanner.scanFolder(testFolder, function (file, infected, data) {
            if (file === excludedFolder && data === "Excluded folder") {
                done();
            }
        });
    });
    
    it("exclude folder - include pattern", function (done) {
        var excludedFolder = path.join(testFolder, "excluded");
        
        var scanner = new rokki.Scanner({ 
            recursive: true,
            includeFolders: /^[d|s]+/ig,
        });
        
        scanner.scanFolder(testFolder, function (file, infected, data) {
            if (file === excludedFolder && data === "Excluded folder") {
                done();
            }
        });
    });
    
});

describe("Whitelist", function () {
    
    var whitelist = new Whitelist();
    
    it ("calculate SHA1 checksum", function (done) {
        var target = path.join(testFolder, "big.txt");
        whitelist.checksum(target, function (err, sha1) {
            assert.strictEqual(sha1, "56e6f70b11c1fa123a4d7e0f4be0fa7674edbd0f"); 
            done();
        });
    });
    
    it ("update database - add a file", function (done) {
        var target = path.join(testFolder, "big.txt");
        whitelist.updateFile(target, "Test", function (err, file, sha1) {
            assert.strictEqual(err, null);
            assert.strictEqual(file, target);
            assert.strictEqual(sha1, "56e6f70b11c1fa123a4d7e0f4be0fa7674edbd0f");
            done();
        });
    });
    
    it ("update database - add missing file", function (done) {
        var target = path.join(testFolder, "missing.txt");
        whitelist.updateFile(target, "Test", function (err, file, sha1) {
            assert.notStrictEqual(err, null);
            assert.strictEqual(file, null);
            assert.strictEqual(sha1, null);
            done();
        });
    });
    
    it ("file is in whitelist", function (done) {
        var target = path.join(testFolder, "subfolder");
        whitelist.update(target, "Test", function (err, file, sha1) {
            assert.strictEqual(err, null);
            whitelist.isInWhitelist(sha1, function (result, filename, product) {
                assert.strictEqual(true, result);
                assert.strictEqual(filename, file);
                assert.strictEqual(product, "Test");
                done(); 
            });
        });
    });
    
    it ("file is not in whitelist", function (done) {
        var target = path.join(testFolder, "subfolder");
        whitelist.update(target, "Test", function (err, file, sha1) {
            assert.strictEqual(err, null);
            whitelist.isInWhitelist("caa8c02a9b471a486466ec6368b349db3fa84984", function (result, filename, product) {
                assert.strictEqual(false, result);
                assert.strictEqual(filename, null);
                assert.strictEqual(product, null);
                done(); 
            });
        });
    });
    
});