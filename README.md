# tlsclient
How small can a TLS/crypto library be?

# 1. Introduction
Some time ago I was developing a web app for my own business, that should be fully web-based, but still communicate with peripherals on the client side.
One possible solution seemed to be writing a browser extension, but then I would have to write one for each browser that would support my app. Besides, I stumbled upon one announcement from Google that they would be removing support for native messaging in the extensions.
The other was developing a native app for communicating with the server directly, basically an HTTPS client. But at first that seemed to involve importing OpenSSL (54 megabytes code) into my project. By that time, I had a very unreliable 3G/4G connection, and a download of an executable that size was likely to fail.
So I thought about importing just the parts of OpenSSL I would need to barely establish the HTTPS connection.
