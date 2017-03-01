var njsx509;
try {
	njsx509 = require(__dirname + '/../build/Debug/NJSX509.node');
} catch(e) {
	njsx509 = require(__dirname + '/../build/Release/NJSX509.node');
}
module.exports = njsx509;
