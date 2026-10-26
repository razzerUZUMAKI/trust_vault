// redact.js
// Masks sensitive data in a message BEFORE it is sent to an external AI.
// Runs locally on our own server. URLs are kept intact on purpose.

// Luhn check: used to make sure a long number is really a card number
function passesLuhn(digits) {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = Number(digits[i]);
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function redact(text) {
  const masked = []; // which TYPES of data were hidden (never the values)

  // Helper: replace matches with a label and remember the type
  const mask = (input, regex, label) =>
    input.replace(regex, () => {
      masked.push(label);
      return `[${label}]`;
    });

  let out = text;

  // 1. Emails
  out = mask(out, /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, "EMAIL");

  // 2. Protect URLs: swap them with placeholders so the number rules below
  //    cannot touch them. They are restored at the end.
  const urls = [];
  const protectUrl = (m) => {
    urls.push(m);
    return `__URL_${urls.length - 1}__`;
  };
  out = out.replace(/\b(?:https?:\/\/|www\.)[^\s<>"']+/gi, protectUrl);
  out = out.replace(
    /\b(?:[a-z0-9-]+\.)+(?:com|in|net|org|xyz|ly|co|link|top|info|online|site|click|app|me|io|cc|tk|ml|gq|ga|cf)\b(?:\/[^\s<>"']*)?/gi,
    protectUrl
  );

  // 3. UPI IDs (name@bank, no dot after the @)
  out = mask(out, /\b[\w.\-]{2,}@[a-zA-Z]{2,}\b/g, "UPI_ID");

  // 4. PAN (ABCDE1234F) and IFSC (SBIN0001234)
  out = mask(out, /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g, "PAN");
  out = mask(out, /\b[A-Z]{4}0[A-Z0-9]{6}\b/g, "IFSC");

  // 5. Passwords, CVV, MPIN: keep the word, hide the value
  out = out.replace(
    /\b(password|passcode|passwd|pwd|mpin|cvv|cvc|atm pin|upi pin)\b(\s*(?:is|:|=|-)?\s*)([^\s,;]*[\d@#$!%&*][^\s,;]*)/gi,
    (m, word, sep) => {
      masked.push("SECRET");
      return `${word}${sep}[SECRET]`;
    }
  );

  // 6. OTP: digits near the words otp / code / pin (either order)
  out = out.replace(
    /\b(otp|one[- ]time (?:password|pin|code)|verification code|security code|code|pin)\b([^\d\n]{0,30}?)(\d{4,8})(?!\d)/gi,
    (m, word, between) => {
      masked.push("OTP");
      return `${word}${between}[OTP]`;
    }
  );
  out = out.replace(
    /(?<!\d)(\d{4,8})(?!\d)(?=[^\n]{0,25}\b(?:otp|code|pin)\b)/gi,
    () => {
      masked.push("OTP");
      return "[OTP]";
    }
  );

  // 7. Card numbers (13-19 digits, must pass the Luhn check)
  out = out.replace(/(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)/g, (m) => {
    const digits = m.replace(/\D/g, "");
    if (passesLuhn(digits)) {
      masked.push("CARD_NUMBER");
      return "[CARD_NUMBER]";
    }
    return m; // not a card, leave it for the next rules
  });

  // 8. Indian phone numbers (with or without +91, spaces allowed)
  out = mask(out, /(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)/g, "PHONE");

  // 9. Aadhaar (12 digits, groups of 4 allowed)
  out = mask(out, /(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?![\s-]?\d)/g, "AADHAAR");

  // 10. Any other long number (9-18 digits) is treated as an account number
  out = mask(out, /(?<!\d)\d{9,18}(?!\d)/g, "ACCOUNT_NUMBER");

  // 11. Put the original URLs back
  out = out.replace(/__URL_(\d+)__/g, (m, i) => urls[Number(i)]);

  return { redacted: out, masked };
}

module.exports = { redact };