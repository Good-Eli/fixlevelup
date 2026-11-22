// Platform-neutral grammar shared by the server's bounded byte decoder and
// the browser's bounded response reader. JSON.parse sees individual string
// tokens only; duplicate decoded members are refused before information loss.
export const P04_JSON_MAX_BYTES = 2 * 1024 * 1024;
export const P04_JSON_MAX_DEPTH = 64;
export const P04_JSON_MAX_NODES = 100_000;

export type P04Json = null | boolean | string | number | P04Json[] | { [key: string]: P04Json };

function invalid(): never { throw new TypeError('Invalid pricing JSON'); }

export function requireP04JsonScalar(text: string): void {
  for (let index = 0; index < text.length; index += 1) {
    const unit = text.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      index += 1;
      const next = text.charCodeAt(index);
      if (!(next >= 0xdc00 && next <= 0xdfff)) { invalid(); }
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      invalid();
    }
  }
}

/** Call only after the route-specific byte limit and strict UTF-8 decoding. */
export function parseP04JsonText(text: string): P04Json {
  if (text.length > P04_JSON_MAX_BYTES) { invalid(); }
  let offset = 0;
  let nodes = 0;
  const integer = /-?(?:0|[1-9][0-9]{0,15})/y;

  function space(): void {
    while (text[offset] === ' ' || text[offset] === '\t' || text[offset] === '\r' || text[offset] === '\n') { offset += 1; }
  }

  function readString(): string {
    const start = offset++;
    while (offset < text.length) {
      const char = text[offset++];
      if (char === '\\') {
        offset += 1;
      } else if (char === '"') {
        let value: string;
        try { value = JSON.parse(text.slice(start, offset)) as string; }
        catch { return invalid(); }
        requireP04JsonScalar(value);
        return value;
      }
    }
    return invalid();
  }

  function readObject(depth: number): { [key: string]: P04Json } {
    const result = Object.create(null) as { [key: string]: P04Json };
    offset += 1;
    space();
    if (text[offset] === '}') { offset += 1; return result; }
    while (text[offset] === '"') {
      const key = readString();
      if (Object.hasOwn(result, key)) { invalid(); }
      space();
      if (text[offset++] !== ':') { invalid(); }
      result[key] = readValue(depth + 1);
      space();
      const next = text[offset++];
      if (next === '}') { return result; }
      if (next !== ',') { invalid(); }
      space();
    }
    return invalid();
  }

  function readArray(depth: number): P04Json[] {
    const result: P04Json[] = [];
    offset += 1;
    space();
    if (text[offset] === ']') { offset += 1; return result; }
    while (offset < text.length) {
      result.push(readValue(depth + 1));
      space();
      const next = text[offset++];
      if (next === ']') { return result; }
      if (next !== ',') { invalid(); }
    }
    return invalid();
  }

  function readValue(depth: number): P04Json {
    nodes += 1;
    if (depth > P04_JSON_MAX_DEPTH || nodes > P04_JSON_MAX_NODES) { invalid(); }
    space();
    switch (text[offset]) {
      case '{': return readObject(depth);
      case '[': return readArray(depth);
      case '"': return readString();
      case 't':
        if (!text.startsWith('true', offset)) { invalid(); }
        offset += 4;
        return true;
      case 'f':
        if (!text.startsWith('false', offset)) { invalid(); }
        offset += 5;
        return false;
      case 'n':
        if (!text.startsWith('null', offset)) { invalid(); }
        offset += 4;
        return null;
      default: {
        integer.lastIndex = offset;
        const token = integer.exec(text)?.[0];
        if (token === undefined || token === '-0') { invalid(); }
        const value = Number(token);
        if (!Number.isSafeInteger(value)) { invalid(); }
        offset = integer.lastIndex;
        return value;
      }
    }
  }

  const result = readValue(1);
  space();
  if (offset !== text.length) { invalid(); }
  return result;
}
