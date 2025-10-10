const rpID = Deno.env.get("RP_ID") ?? "kbn.one";
const rpName = Deno.env.get("RP_NAME") ?? "kbn.one";

export { rpID, rpName };
