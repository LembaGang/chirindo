// A validator for the JSON Schema keywords the output schema of spec D.3 uses
// (type, enum, const, required, additionalProperties, properties, items,
// pattern, minimum, $ref into $defs), so that the output can be checked
// without a new dependency. A keyword it does not know is an error, never
// skipped. Returns the list of violations (empty when the value is valid).

const KNOWN = new Set(["$schema", "title", "type", "enum", "const", "required", "additionalProperties", "properties", "items", "pattern", "minimum", "$ref", "$defs"]);

function typeOf(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  if (typeof v === "number") return Number.isInteger(v) ? "integer" : "number";
  return typeof v;
}
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

export function validate(schema, value, root = schema, at = "$") {
  const errs = [];
  for (const k of Object.keys(schema)) if (!KNOWN.has(k)) errs.push(`${at}: the schema uses a keyword this validator does not know: ${k}`);
  if (schema.$ref !== undefined) {
    const m = /^#\/\$defs\/(.+)$/.exec(schema.$ref);
    if (!m || !root.$defs?.[m[1]]) return [...errs, `${at}: unresolvable $ref ${schema.$ref}`];
    errs.push(...validate(root.$defs[m[1]], value, root, at));
  }
  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    const t = typeOf(value);
    if (!types.includes(t) && !(t === "integer" && types.includes("number"))) {
      errs.push(`${at}: type ${t}, not ${types.join(" or ")}`);
      return errs;
    }
  }
  if (schema.enum !== undefined && !schema.enum.some((e) => same(e, value))) errs.push(`${at}: ${JSON.stringify(value)} is not one of the enum`);
  if (schema.const !== undefined && !same(schema.const, value)) errs.push(`${at}: not the const ${JSON.stringify(schema.const)}`);
  if (schema.pattern !== undefined && typeof value === "string" && !new RegExp(schema.pattern, "u").test(value)) errs.push(`${at}: ${JSON.stringify(value)} does not match ${schema.pattern}`);
  if (schema.minimum !== undefined && typeof value === "number" && value < schema.minimum) errs.push(`${at}: ${value} is below ${schema.minimum}`);
  if (typeOf(value) === "object") {
    for (const r of schema.required ?? []) if (!Object.prototype.hasOwnProperty.call(value, r)) errs.push(`${at}: lacks required ${r}`);
    const props = schema.properties ?? {};
    for (const [k, v] of Object.entries(value)) {
      if (Object.prototype.hasOwnProperty.call(props, k)) errs.push(...validate(props[k], v, root, `${at}.${k}`));
      else if (schema.additionalProperties === false) errs.push(`${at}: has a member the schema does not allow: ${k}`);
    }
  }
  if (typeOf(value) === "array" && schema.items !== undefined) value.forEach((v, i) => errs.push(...validate(schema.items, v, root, `${at}[${i}]`)));
  return errs;
}
