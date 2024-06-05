var mysql = require('mysql');
    
    var con = mysql.createConnection({
      user: "root",
      password: "march212",
      insecureAuth : true
    });
    
    con.connect(function(err) {
      if (err) throw err;
      console.log("Connected!");
    });