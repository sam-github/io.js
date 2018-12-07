const util = require('util');
const _ = require('crypto').scratch;

console.log('const scratch = ' + _);

function scratch(v, die) {
  console.log('===== scratch(', util.inspect(v), ',', !!die, ')');
  try {
    console.log('returns:', _(v, die));
  } catch (er) {
    console.log('throws:', er.message);
  }
}

scratch(1.1);
scratch();
scratch('12');
scratch(null);
scratch(-3);
scratch(12);
scratch(function () { const hello=0; });
scratch(true);
