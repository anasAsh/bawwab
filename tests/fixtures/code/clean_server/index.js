const { z } = require("zod");

const schema = z.object({ name: z.string() });

function greet(input) {
  const { name } = schema.parse(input);
  return `hello ${name} from ${process.env.NODE_ENV}`;
}

module.exports = { greet };
