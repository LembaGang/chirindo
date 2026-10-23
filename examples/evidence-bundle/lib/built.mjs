// What this build implements: the id of every check of spec table 4-2 whose
// code is here, and a tag for each binding rule that a widening of the shape
// this build judges needs (README.md, "The shape this build judges"). Each id
// is added beside the code that implements it, so that test/unlocks.mjs can
// tie every property the allow-list judges to the checks it needs. The online
// checks (O1 to O7) are listed NOT-EVALUATED offline and are not built.

export const BUILT = new Set();
export const built = (...ids) => {
  for (const id of ids) BUILT.add(id);
};
