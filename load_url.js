//includes
var system = require('system');
var webPage = require('webpage');
var fs = require('fs');

//global vars
var page = webPage.create();
page.settings.webSecurityEnabled = false;
page.settings.localToRemoteUrlAccessEnabled = true;
var args = system.args;
var arg1 = args[1];
var arg2 = args[2];
var redirectUrls = {};

//format arg1 with http:// if necessary
url = arg1.indexOf("http://") == -1 ? ("http://" + arg1) : arg1;

var hostname = arg2;

//capture any navigation (redirect) events
page.onNavigationRequested = function(aURL, type, willNavigate, main) {
	if (main == true && (aURL != url && aURL != url + '/')){
		//print out whenever there is a redirect url
		//console.log('New URL: ' + aURL);
		//add url to hash - table
  		redirectUrls[aURL] = true;
	}
};

page.open(url, function (status) {
    if (status !== 'success') {
        console.log('Unable to load the address!');
        phantom.exit();
    } else {
        //use the default time of 1000 milliseconds
        window.setTimeout(function () {
            //next we save off the html of the page to output.txt
            var path = hostname + '-output.txt';
            var content = page.content;
            fs.write(path, content, 'w');

            //first we save off a screen shot of the webpage
            page.render(hostname + "-screenie.jpeg");

            //print out the number of redirects we find
            console.log("\nRedirects: " + Object.keys(redirectUrls).length + "\n");

            phantom.exit();
        }, 1000); // Change timeout as required to allow sufficient time 
    }
});

