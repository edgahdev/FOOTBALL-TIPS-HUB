const bcrypt = require("bcryptjs");
const readline = require("readline");
const rl = readline.createInterface({input:process.stdin,output:process.stdout});
rl.question("Choose a strong admin password (input visible): ", async p=>{
 if(p.length<12){console.error("Use at least 12 characters.");process.exit(1)}
 console.log("\nPut this hash in .env as ADMIN_PASSWORD_HASH:\n"+await bcrypt.hash(p,12));
 rl.close();
});
