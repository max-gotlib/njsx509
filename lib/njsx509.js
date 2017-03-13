//
//  njsx509.js
//  njsx509
//
//  Created by Maxim Gotlib on 2/28/17.
//  Copyright © 2017 Maxim Gotlib. All rights reserved.
//

var njsx509;
try {
	njsx509 = require(__dirname + '/../build/Debug/NJSX509.node');
} catch(e) {
	njsx509 = require(__dirname + '/../build/Release/NJSX509.node');
}
module.exports = njsx509;
