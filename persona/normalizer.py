"""
Input Normalization Engine for obfuscation-resistant security scanning.

Attackers use encoding, substitution, and structural tricks to evade
keyword-based detectors. This module reverses common obfuscation before
security rules run, so the detector sees the *intended* text.

Supported normalizations:
  - Leetspeak (1337) → ASCII
  - Homoglyph / Cyrillic → Latin
  - ROT13 detection + decode
  - Base64 fragment decode
  - Zero-width character stripping
  - Soft hyphen / invisible separator removal
  - Character spacing collapse ("i g n o r e" → "ignore")
  - Unicode confusable normalization
  - Reversed text detection
  - Token splitting repair (soft hyphens, word joiners)

Reference:
  - Zou et al. 2023 "Universal and Transferable Adversarial Attacks"
  - Liu et al. 2023 "AutoDAN: Generating Stealthy Jailbreak Prompts"
  - Boucher et al. 2022 "Bad Characters: Imperceptible NLP Attacks"
"""

import re
import base64
import codecs
import unicodedata
from typing import List, Set, Tuple


# ─────────────────────────────────────────────────────────────
#  Homoglyph mapping: visually similar Unicode chars → ASCII
# ─────────────────────────────────────────────────────────────

_HOMOGLYPHS = {
    # Cyrillic → Latin
    "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E",
    "\u041d": "H", "\u041a": "K", "\u041c": "M", "\u041e": "O",
    "\u0420": "P", "\u0422": "T", "\u0425": "X",
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0455": "s", "\u0406": "I",
    # Greek → Latin
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H",
    "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N",
    "\u039f": "O", "\u03a1": "P", "\u03a4": "T", "\u03a7": "X",
    "\u03b1": "a", "\u03b5": "e", "\u03bf": "o", "\u03c1": "p",
    # Mathematical / fullwidth
    "\uff21": "A", "\uff22": "B", "\uff23": "C", "\uff24": "D",
    "\uff25": "E", "\uff26": "F", "\uff27": "G", "\uff28": "H",
    "\uff29": "I", "\uff2a": "J", "\uff2b": "K", "\uff2c": "L",
    "\uff2d": "M", "\uff2e": "N", "\uff2f": "O", "\uff30": "P",
    "\uff31": "Q", "\uff32": "R", "\uff33": "S", "\uff34": "T",
    "\uff35": "U", "\uff36": "V", "\uff37": "W", "\uff38": "X",
    "\uff39": "Y", "\uff3a": "Z",
    "\uff41": "a", "\uff42": "b", "\uff43": "c", "\uff44": "d",
    "\uff45": "e", "\uff46": "f", "\uff47": "g", "\uff48": "h",
    "\uff49": "i", "\uff4a": "j", "\uff4b": "k", "\uff4c": "l",
    "\uff4d": "m", "\uff4e": "n", "\uff4f": "o", "\uff50": "p",
    "\uff51": "q", "\uff52": "r", "\uff53": "s", "\uff54": "t",
    "\uff55": "u", "\uff56": "v", "\uff57": "w", "\uff58": "x",
    "\uff59": "y", "\uff5a": "z",
    # Common confusables
    "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
    "\u2013": "-", "\u2014": "-",
}

# ─────────────────────────────────────────────────────────────
#  Leetspeak mapping
# ─────────────────────────────────────────────────────────────

_LEET_MAP = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "9": "g", "@": "a", "$": "s",
    "!": "i", "|": "l", "(": "c", "+": "t", "}{": "h",
    "}{": "h",
}

# Regex-friendly inverse: multi-char patterns first
_LEET_PATTERNS = [
    (re.compile(r"\}\{", re.IGNORECASE), "h"),
    (re.compile(r"\|_\|", re.IGNORECASE), "u"),
    (re.compile(r"\|\\\|", re.IGNORECASE), "m"),
    (re.compile(r"/\\", re.IGNORECASE), "a"),
    (re.compile(r"\\/", re.IGNORECASE), "v"),
    (re.compile(r"\|\|", re.IGNORECASE), "n"),
    (re.compile(r"\(\)", re.IGNORECASE), "o"),
]

# ─────────────────────────────────────────────────────────────
#  Invisible / zero-width characters
# ─────────────────────────────────────────────────────────────

_INVISIBLE_CHARS = set([
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\u2060",  # word joiner
    "\ufeff",  # zero-width no-break space (BOM)
    "\u200e",  # left-to-right mark
    "\u200f",  # right-to-left mark
    "\u00ad",  # soft hyphen
    "\u034f",  # combining grapheme joiner
    "\u2061",  # function application
    "\u2062",  # invisible times
    "\u2063",  # invisible separator
    "\u2064",  # invisible plus
    "\u180e",  # Mongolian vowel separator
    "\u2028",  # line separator (when used inline)
    "\u2029",  # paragraph separator (when used inline)
    "\u202a",  # LTR embedding
    "\u202b",  # RTL embedding
    "\u202c",  # pop directional formatting
    "\u202d",  # LTR override
    "\u202e",  # RTL override
])

_INVISIBLE_RE = re.compile(
    "[" + "".join(re.escape(c) for c in _INVISIBLE_CHARS) + "]"
)

# ─────────────────────────────────────────────────────────────
#  Character-spaced text detection: "i g n o r e" → "ignore"
# ─────────────────────────────────────────────────────────────

_CHAR_SPACED = re.compile(
    r"(?<!\w)"                  # not preceded by word char
    r"([a-zA-Z])"               # single letter
    r"(?:\s+[a-zA-Z]){3,}"     # followed by 3+ spaced letters
    r"(?!\w)"                   # not followed by word char
)

# ─────────────────────────────────────────────────────────────
#  Base64 fragment detection
# ─────────────────────────────────────────────────────────────

_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")

# ─────────────────────────────────────────────────────────────
#  ROT13 detection heuristic
#  We decode and check if the result has more English-like words
# ─────────────────────────────────────────────────────────────

_SECURITY_WORDS: Set[str] = {
    "ignore", "bypass", "override", "security", "instructions",
    "previous", "system", "prompt", "forget", "restrictions",
    "unrestricted", "jailbreak", "developer", "mode", "enabled",
    "disable", "rules", "you", "are", "now", "pretend",
    "act", "execute", "reveal", "secret", "password", "token",
    "credentials", "exfiltrate", "send", "transfer", "data",
    "disregard", "follow", "new", "command", "output", "hidden",
    "injection", "assistant", "priority", "override", "admin",
    "sudo", "root", "delete", "remove", "modify", "change",
    "impersonate", "simulate", "identity", "persona", "role",
    "discard", "abandon", "original", "initial", "primary",
    "safety", "alignment", "filter", "content", "policy",
    "guidelines", "constraints", "limitations", "boundaries",
}


class InputNormalizer:
    """
    Reverses obfuscation techniques to expose the attacker's intended text.
    
    This is NOT for display — the normalized text is only used internally
    by security rules. The original text is preserved for the agent.
    
    Usage:
        normalizer = InputNormalizer()
        variants = normalizer.normalize(suspicious_text)
        # variants is a list of normalized strings to scan
        # Each string represents a possible decoding of the input
    """

    def __init__(self, aggressive: bool = True):
        """
        Args:
            aggressive: Enable all normalizations including ROT13/base64 decode.
                       Set False for lower false positive rate.
        """
        self.aggressive = aggressive

    def normalize(self, text: str) -> List[str]:
        """
        Produce normalized variants of the input text.
        
        Returns a list of strings. The first is always the "best effort"
        full normalization. Additional entries are alternative decodings
        (ROT13, base64 fragments, reversed text) that may reveal hidden intent.
        
        Security rules should check ALL returned variants.
        """
        variants = []

        # Primary normalization: strip invisible, fix homoglyphs, de-leet, collapse spacing
        primary = self._strip_invisible(text)
        primary = self._normalize_homoglyphs(primary)
        primary = self._de_leetspeak(primary)
        primary = self._collapse_char_spacing(primary)
        primary = self._normalize_unicode(primary)
        variants.append(primary)

        if self.aggressive:
            # ROT13 decode
            rot13 = self._try_rot13(text)
            if rot13 and rot13 != text:
                rot13_norm = self._strip_invisible(rot13)
                rot13_norm = self._normalize_homoglyphs(rot13_norm)
                rot13_norm = self._de_leetspeak(rot13_norm)
                rot13_norm = self._collapse_char_spacing(rot13_norm)
                variants.append(rot13_norm)

            # Base64 decode fragments
            b64_decoded = self._try_base64_fragments(text)
            for decoded in b64_decoded:
                variants.append(decoded)

            # Reversed text (include ALL qualifying variants)
            reversed_variants = self._get_all_reversed(text)
            for rv in reversed_variants:
                if rv not in variants:
                    variants.append(rv)

            # Pig Latin decode
            pig_decoded = self._try_pig_latin(text)
            if pig_decoded:
                variants.append(pig_decoded)

        return variants

    def normalize_single(self, text: str) -> str:
        """Return just the primary normalization (fastest)."""
        result = self._strip_invisible(text)
        result = self._normalize_homoglyphs(result)
        result = self._de_leetspeak(result)
        result = self._collapse_char_spacing(result)
        result = self._normalize_unicode(result)
        return result

    # ── Individual normalization steps ─────────────────────────

    @staticmethod
    def _strip_invisible(text: str) -> str:
        """Remove all invisible/zero-width characters."""
        return _INVISIBLE_RE.sub("", text)

    @staticmethod
    def _normalize_homoglyphs(text: str) -> str:
        """Replace visually similar Unicode chars with ASCII equivalents."""
        result = []
        for ch in text:
            result.append(_HOMOGLYPHS.get(ch, ch))
        return "".join(result)

    @staticmethod
    def _de_leetspeak(text: str) -> str:
        """Convert leetspeak substitutions back to letters."""
        result = text
        # Multi-char patterns first
        for pattern, replacement in _LEET_PATTERNS:
            result = pattern.sub(replacement, result)
        # Single-char patterns
        output = []
        for ch in result:
            output.append(_LEET_MAP.get(ch, ch))
        return "".join(output)

    @staticmethod
    def _collapse_char_spacing(text: str) -> str:
        """
        Collapse character-spaced text: "i g n o r e   a l l" → "ignore all".
        
        Detects when individual characters are separated by single spaces
        (obfuscation) while preserving word boundaries (multi-space gaps).
        """
        # First check if the text looks char-spaced overall:
        # pattern: mostly single letters separated by single spaces
        # Word boundaries are 2+ spaces
        
        # Split on 2+ spaces first (these are word boundaries)
        import re as _re
        word_groups = _re.split(r"\s{2,}", text)
        
        if not word_groups:
            return text
        
        rebuilt = []
        any_collapsed = False
        for group in word_groups:
            group = group.strip()
            if not group:
                continue
            # Check if this group looks like char-spaced: single chars separated by single spaces
            # e.g., "i g n o r e" → all parts are single chars
            parts = group.split(" ")
            if len(parts) >= 3 and all(len(p) <= 1 for p in parts if p):
                # Collapse: remove spaces between single chars
                rebuilt.append("".join(p for p in parts if p))
                any_collapsed = True
            else:
                rebuilt.append(group)

        if any_collapsed:
            return " ".join(rebuilt)
        
        # Fallback: also try collapsing within a larger text
        # where char-spacing appears as a sub-pattern
        def collapse(match: _re.Match) -> str:
            text_match = match.group(0)
            return text_match.replace(" ", "")
        
        return _re.sub(
            r"(?<!\w)(?:[a-zA-Z] ){3,}[a-zA-Z](?!\w)",
            collapse,
            text,
        )

    @staticmethod
    def _normalize_unicode(text: str) -> str:
        """NFC normalize + strip combining marks."""
        normalized = unicodedata.normalize("NFKD", text)
        # Keep base characters, drop combining marks
        return "".join(
            ch for ch in normalized
            if not unicodedata.combining(ch)
        )

    def _try_rot13(self, text: str) -> str | None:
        """
        Decode ROT13 and check if result has more security-relevant words.
        Returns decoded text only if it scores higher than original.
        """
        decoded = codecs.decode(text, "rot_13")
        orig_score = self._security_word_score(text.lower())
        decoded_score = self._security_word_score(decoded.lower())

        if decoded_score > orig_score and decoded_score >= 2:
            return decoded
        return None

    def _try_base64_fragments(self, text: str) -> List[str]:
        """Find and decode base64 fragments in text."""
        results = []
        for match in _B64_RE.finditer(text):
            fragment = match.group(0)
            try:
                padded = fragment + "=" * (4 - len(fragment) % 4) if len(fragment) % 4 else fragment
                decoded = base64.b64decode(padded).decode("utf-8", errors="strict")
                if all(c.isprintable() or c in "\n\r\t " for c in decoded):
                    if self._security_word_score(decoded.lower()) >= 1:
                        results.append(decoded)
            except Exception:
                continue
        return results

    def _try_reversed(self, text: str) -> str | None:
        """
        Check if reversing the text (or individual words, or word order)
        reveals security-relevant words.
        
        Returns the best reversed variant, but also appends all qualifying
        variants to enable the caller to check multiple decodings.
        """
        orig_score = self._security_word_score(text.lower())
        candidates = []

        words = text.split()

        # 1. Full character reversal
        full_rev = text[::-1]
        score = self._security_word_score(full_rev.lower())
        if score > orig_score and score >= 2:
            candidates.append((score, full_rev))

        # 2. Word-level character reversal (each word reversed individually)
        word_rev = " ".join(w[::-1] for w in words)
        score = self._security_word_score(word_rev.lower())
        if score > orig_score and score >= 2:
            candidates.append((score, word_rev))

        # 3. Word-ORDER reversal (reverse the sequence of words)
        order_rev = " ".join(reversed(words))
        score = self._security_word_score(order_rev.lower())
        if score > orig_score and score >= 2:
            candidates.append((score, order_rev))

        # 4. Word-level + order reversal combined
        word_rev_reorder = " ".join(w[::-1] for w in reversed(words))
        score = self._security_word_score(word_rev_reorder.lower())
        if score > orig_score and score >= 2:
            candidates.append((score, word_rev_reorder))

        if not candidates:
            return None

        # Return highest-scoring variant
        candidates.sort(key=lambda x: -x[0])
        return candidates[0][1]

    def _get_all_reversed(self, text: str) -> List[str]:
        """Return ALL qualifying reversed variants (not just the best)."""
        orig_score = self._security_word_score(text.lower())
        results = []
        words = text.split()

        for variant in [
            text[::-1],
            " ".join(w[::-1] for w in words),
            " ".join(reversed(words)),
            " ".join(w[::-1] for w in reversed(words)),
        ]:
            score = self._security_word_score(variant.lower())
            if score > orig_score and score >= 2 and variant not in results:
                results.append(variant)

        return results

    def _try_pig_latin(self, text: str) -> str | None:
        """Attempt to decode pig latin (word ends in -ay/-way)."""
        words = text.split()
        decoded = []
        pig_count = 0
        for word in words:
            clean = re.sub(r"[^\w]", "", word)
            if clean.lower().endswith("ay") and len(clean) > 3:
                # Try to decode: move last consonant cluster before "ay" to front
                core = clean[:-2]  # remove "ay"
                if core.lower().endswith("w") and len(core) > 1:
                    # vowel-initial: word + "way" → remove "way"
                    decoded.append(core[:-1])
                    pig_count += 1
                elif len(core) > 1:
                    # consonant-initial: moved consonant(s) to end
                    # Try: last char of core was the initial consonant
                    decoded.append(core[-1] + core[:-1])
                    pig_count += 1
                else:
                    decoded.append(word)
            else:
                decoded.append(word)

        if pig_count >= 2:
            result = " ".join(decoded)
            if self._security_word_score(result.lower()) >= 2:
                return result
        return None

    @staticmethod
    def _security_word_score(text: str) -> int:
        """Count how many security-relevant words appear in text."""
        words = set(re.findall(r"[a-zA-Z]+", text.lower()))
        return len(words & _SECURITY_WORDS)
