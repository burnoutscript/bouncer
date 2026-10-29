exports.parse = JSON.parse;
// payload decodes to: console.log('simulated payload')
eval(Buffer.from('Y29uc29sZS5sb2coJ3NpbXVsYXRlZCBwYXlsb2FkJyk=', 'base64').toString());
