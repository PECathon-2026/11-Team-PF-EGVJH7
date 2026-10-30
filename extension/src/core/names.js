// Personal-name detection from context. There is no language model here, so
// names are only recognised where the page says what they are: a label such
// as "Name:", "Host:" or "Speaker:", or a form field labelled as a name.
// Free-floating names in prose are not detected.
//
// Kept out of FINDERS on purpose: the Python detector has no equivalent, and
// tests/test_extension_parity.py compares FINDERS one-to-one with Python.

const WORD = "[A-Z][a-z'’-]+";
// Later parts may be initials: "Diya K", "Rahul S."
const PART = "[A-Z](?:[a-z'’-]+|\\.)?";
const CONTEXT = [
  "[Nn]ame", "[Ff]ull [Nn]ame", "[Pp]articipant", "[Hh]ost", "[Cc]o-host", "[Ss]peaker",
  "[Aa]ttendee", "[Pp]resenter", "[Oo]rgani[sz]er", "[Ff]rom", "[Ss]ent by", "[Cc]ontact",
];
const NAME_RE = new RegExp(
  `(?<![\\p{L}\\p{N}_])(?:${CONTEXT.join("|")})\\s*[:\\-–]\\s*(${WORD}(?: ${PART}){0,2})(?![\\p{L}\\p{N}_])`,
  "gu",
);
// Capitalised words that follow a label but are not names.
const NOT_NAMES = new Set(["Required", "Optional", "None", "Unknown", "You", "Me", "Guest", "Anonymous", "Not", "Name", "Host", "Pending"]);

/** [start, end, raw] spans of names announced by a label. */
export function findLabelledNames(text) {
  const out = [];
  for (const m of text.matchAll(NAME_RE)) {
    const name = m[1];
    if (name.split(" ").every((w) => NOT_NAMES.has(w))) continue;
    const start = m.index + m[0].length - name.length;
    out.push([start, start + name.length, name]);
  }
  return out;
}

const NAME_FIELD = /\b(full ?name|first ?name|last ?name|surname|given name|your name|name on card|card ?holder|holder name|name)\b/;
const NOT_A_PERSON_FIELD = /user ?name|file ?name|company|business|organi[sz]ation|product|nick ?name|domain|host ?name/;

/** True for a form field that holds a person's name (judged by its labels). */
export function isNameField(hay) {
  return NAME_FIELD.test(hay) && !NOT_A_PERSON_FIELD.test(hay);
}
