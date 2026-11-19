// Inert fixture: the decoded string is console.log(1).
eval(Buffer.from("Y29uc29sZS5sb2coMSk=", "base64").toString());
