// Integers in the rules file may be JSON numbers or strings like "0x1FF".
// Mirrors eaglegate_validate.to_int, i.e. Python's int(text, 0): hex, octal
// (0o), binary and plain decimal, but no leading zeros ("010" is refused).
const INT_LITERAL = {
  16: /^([+-]?)0x([0-9a-f](?:_?[0-9a-f])*)$/i,
  8: /^([+-]?)0o([0-7](?:_?[0-7])*)$/i,
  2: /^([+-]?)0b([01](?:_?[01])*)$/i,
  10: /^([+-]?)([1-9](?:_?\d)*|0+)$/,
}

export function toInt(value) {
  if (typeof value === 'number') return Number.isInteger(value) ? value : NaN
  if (typeof value !== 'string') return NaN // booleans are refused too
  const text = value.trim()
  for (const [base, pattern] of Object.entries(INT_LITERAL)) {
    const found = pattern.exec(text)
    if (found) {
      const n = parseInt(found[2].replaceAll('_', ''), Number(base))
      return found[1] === '-' ? -n : n
    }
  }
  return NaN
}
