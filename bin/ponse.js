#!/usr/bin/env node

(function() {
    'use strict';
    
    var DIR         = process.cwd(),
        
        ponse       = require('../'),
        http        = require('http'),
        
        server      = http.createServer(ponse.static(DIR)),
        
        port        =   process.env.PORT            ||  /* c9           */
                        process.env.app_port        ||  /* nodester     */
                        process.env.VCAP_APP_PORT   ||  /* cloudfoundry */
                        1337,
        
        ip          =   process.env.IP              ||  /* c9           */
                        '0.0.0.0';
        
        server.listen(port, ip);
        
        console.log('dir:', DIR);
        console.log('url: http://' + ip + ':' + port);
})();
