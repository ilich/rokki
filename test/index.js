"use strict";

var assert = require("assert"),
    path = require("path"),
    rokki = require(".."); 

describe("Malware Scanner", function () {
    
    function notFound(expectedFile, file, infected, data) {
        assert.strictEqual(file, expectedFile);
        assert.strictEqual(infected, null);
        assert.strictEqual(data, "File is not found");
    }
    
    function excluded(expectedFile, file, infected, data) {
        assert.strictEqual(file, expectedFile);
        assert.strictEqual(infected, null);
        assert.strictEqual(data, "Excluded");
    }
    
    function tooBig(expectedFile, file, infected, data) {
        assert.strictEqual(file, expectedFile);
        assert.strictEqual(infected, null);
        assert.strictEqual(data, "File is too big");
    }
    
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
    
    
    var scanner = new rokki.Scanner();
    var testFolder = path.join(__dirname, "data");
    
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
    
});