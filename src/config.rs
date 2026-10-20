//! Nix-like configuration file parser.
//!
//! Parses the subset of the Nix expression language used by ExtOS
//! configuration files (`manifest.nix`, `system.nix`, `daemons.nix`, etc.).
//!
//! # Supported Syntax
//! - Strings: `"hello"`, `"escape: \n \t \""`, multiline `''...''`
//! - Integers: `42`, `-7`
//! - Booleans: `true`, `false`
//! - Null: `null`
//! - Lists: `[ "a" "b" 42 ]`
//! - Attribute sets: `{ key = value; nested.key = value; }`
//!   (Nix-compatible: the final binding may omit its trailing `';'`,
//!   e.g. `{ name = "glibc" }`; `';'` is still required between bindings)
//! - `rec { }` recursive attribute sets (syntactically accepted, treated as regular attrsets)
//! - Comments: `# line comment`, `/* block comment */`
//! - Identifiers and dotted paths: `foo`, `foo.bar.baz`
//! - String interpolation: `"${expr}"` (parsed as concatenation)
//!
//! # Not Supported (deferred to libexpr-extos)
//! - `let ... in` bindings
//! - `with` expressions
//! - Function definitions / lambdas
//! - `import` / `builtins.*`
//! - `inherit` keyword
//! - Arithmetic / boolean operators

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use crate::error::ExtosError;

// ─── Value AST ──────────────────────────────────────────────────

/// A parsed Nix value (the AST node).
#[derive(Debug, Clone, PartialEq)]
pub enum NixValue {
    /// A string literal.
    String(String),
    /// An integer literal.
    Int(i64),
    /// A boolean literal.
    Bool(bool),
    /// The `null` literal.
    Null,
    /// A list `[ ... ]`.
    List(Vec<NixValue>),
    /// An attribute set `{ key = value; ... }`.
    /// Uses BTreeMap for deterministic ordering.
    AttrSet(BTreeMap<String, NixValue>),
}

impl fmt::Display for NixValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NixValue::String(s) => write!(f, "\"{}\"", s.replace('"', "\\\"")),
            NixValue::Int(n) => write!(f, "{n}"),
            NixValue::Bool(b) => write!(f, "{b}"),
            NixValue::Null => write!(f, "null"),
            NixValue::List(items) => {
                write!(f, "[ ")?;
                for item in items {
                    write!(f, "{item} ")?;
                }
                write!(f, "]")
            }
            NixValue::AttrSet(map) => {
                write!(f, "{{ ")?;
                for (k, v) in map {
                    write!(f, "{k} = {v}; ")?;
                }
                write!(f, "}}")
            }
        }
    }
}

impl NixValue {
    /// Get a nested value by dotted path (e.g., `"identity.name"`).
    pub fn get_path(&self, path: &str) -> Option<&NixValue> {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = self;
        for part in parts {
            match current {
                NixValue::AttrSet(map) => {
                    current = map.get(part)?;
                }
                _ => return None,
            }
        }
        Some(current)
    }

    /// Get as string, returning None if not a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            NixValue::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Get as integer.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            NixValue::Int(n) => Some(*n),
            _ => None,
        }
    }

    /// Get as boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            NixValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Get as list.
    pub fn as_list(&self) -> Option<&[NixValue]> {
        match self {
            NixValue::List(v) => Some(v.as_slice()),
            _ => None,
        }
    }

    /// Get as attribute set.
    pub fn as_attrset(&self) -> Option<&BTreeMap<String, NixValue>> {
        match self {
            NixValue::AttrSet(map) => Some(map),
            _ => None,
        }
    }

    /// Convenience: get a string from a dotted path.
    pub fn get_str(&self, path: &str) -> Option<&str> {
        self.get_path(path)?.as_str()
    }

    /// Convenience: get a string list from a dotted path.
    pub fn get_str_list(&self, path: &str) -> Option<Vec<&str>> {
        let list = self.get_path(path)?.as_list()?;
        list.iter().map(|v| v.as_str()).collect()
    }
}

// ─── Tokenizer ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Token {
    LBrace,      // {
    RBrace,      // }
    LBracket,    // [
    RBracket,    // ]
    Equals,      // =
    Semi,        // ;
    Dot,         // .
    String(String),
    Int(i64),
    Bool(bool),
    Null,
    Ident(String),
    Eof,
}

struct Tokenizer {
    chars: Vec<char>,
    pos: usize,
    line: usize,
}

impl Tokenizer {
    fn new(input: &str) -> Self {
        Self {
            chars: input.chars().collect(),
            pos: 0,
            line: 1,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<char> {
        let ch = self.chars.get(self.pos).copied()?;
        self.pos += 1;
        if ch == '\n' {
            self.line += 1;
        }
        Some(ch)
    }

    fn skip_whitespace_and_comments(&mut self) {
        loop {
            // Skip whitespace
            while self.peek().is_some_and(|c| c.is_whitespace()) {
                self.advance();
            }
            // Skip line comments
            if self.peek() == Some('#') {
                while self.peek().is_some_and(|c| c != '\n') {
                    self.advance();
                }
                continue;
            }
            // Skip block comments /* ... */
            if self.pos + 1 < self.chars.len()
                && self.chars[self.pos] == '/'
                && self.chars[self.pos + 1] == '*'
            {
                self.advance(); // /
                self.advance(); // *
                loop {
                    match self.advance() {
                        Some('*') if self.peek() == Some('/') => {
                            self.advance();
                            break;
                        }
                        None => break,
                        _ => {}
                    }
                }
                continue;
            }
            break;
        }
    }

    fn read_string(&mut self) -> Result<String, ExtosError> {
        // Opening quote already consumed
        let mut s = String::new();
        loop {
            match self.advance() {
                Some('"') => return Ok(s),
                Some('\\') => match self.advance() {
                    Some('n') => s.push('\n'),
                    Some('t') => s.push('\t'),
                    Some('r') => s.push('\r'),
                    Some('"') => s.push('"'),
                    Some('\\') => s.push('\\'),
                    Some('$') => s.push('$'),
                    Some(c) => {
                        s.push('\\');
                        s.push(c);
                    }
                    None => {
                        return Err(ExtosError::ConfigParse {
                            path: String::new(),
                            line: self.line,
                            message: "unexpected EOF in string escape".into(),
                        });
                    }
                },
                Some('$') if self.peek() == Some('{') => {
                    // String interpolation: ${...}
                    // For now, we read the expression as literal text
                    self.advance(); // consume {
                    s.push_str("${");
                    let mut depth = 1;
                    while depth > 0 {
                        match self.advance() {
                            Some('{') => {
                                depth += 1;
                                s.push('{');
                            }
                            Some('}') => {
                                depth -= 1;
                                if depth > 0 {
                                    s.push('}');
                                }
                            }
                            Some(c) => s.push(c),
                            None => {
                                return Err(ExtosError::ConfigParse {
                                    path: String::new(),
                                    line: self.line,
                                    message: "unexpected EOF in string interpolation".into(),
                                });
                            }
                        }
                    }
                    s.push('}');
                }
                Some(c) => s.push(c),
                None => {
                    return Err(ExtosError::ConfigParse {
                        path: String::new(),
                        line: self.line,
                        message: "unterminated string literal".into(),
                    });
                }
            }
        }
    }

    fn read_multiline_string(&mut self) -> Result<String, ExtosError> {
        // Opening '' already consumed
        let mut s = String::new();
        loop {
            match self.advance() {
                Some('\'') if self.peek() == Some('\'') => {
                    // Check for escape sequences ''$ ''\ ''\n etc.
                    let next_next = self.chars.get(self.pos + 1).copied();
                    match next_next {
                        Some('\\') | Some('$') => {
                            self.advance(); // second '
                            let esc = self.advance().unwrap();
                            if esc == '\\' {
                                // ''\n -> newline, ''\t -> tab
                                match self.advance() {
                                    Some('n') => s.push('\n'),
                                    Some('t') => s.push('\t'),
                                    Some(c) => {
                                        s.push('\\');
                                        s.push(c);
                                    }
                                    None => s.push('\\'),
                                }
                            } else {
                                s.push(esc); // literal $
                            }
                        }
                        _ => {
                            self.advance(); // consume second '
                            return Ok(s);
                        }
                    }
                }
                Some(c) => s.push(c),
                None => {
                    return Err(ExtosError::ConfigParse {
                        path: String::new(),
                        line: self.line,
                        message: "unterminated multiline string".into(),
                    });
                }
            }
        }
    }

    fn next_token(&mut self) -> Result<Token, ExtosError> {
        self.skip_whitespace_and_comments();

        match self.peek() {
            None => Ok(Token::Eof),
            Some(c) => match c {
                '{' => {
                    self.advance();
                    Ok(Token::LBrace)
                }
                '}' => {
                    self.advance();
                    Ok(Token::RBrace)
                }
                '[' => {
                    self.advance();
                    Ok(Token::LBracket)
                }
                ']' => {
                    self.advance();
                    Ok(Token::RBracket)
                }
                '=' => {
                    self.advance();
                    Ok(Token::Equals)
                }
                ';' => {
                    self.advance();
                    Ok(Token::Semi)
                }
                '.' => {
                    self.advance();
                    Ok(Token::Dot)
                }
                '"' => {
                    self.advance();
                    Ok(Token::String(self.read_string()?))
                }
                '\'' if self.chars.get(self.pos + 1) == Some(&'\'') => {
                    self.advance(); // first '
                    self.advance(); // second '
                    Ok(Token::String(self.read_multiline_string()?))
                }
                '-' if self.chars.get(self.pos + 1).is_some_and(|c| c.is_ascii_digit()) => {
                    self.advance(); // -
                    let n = self.read_number()?;
                    Ok(Token::Int(-n))
                }
                c if c.is_ascii_digit() => Ok(Token::Int(self.read_number()?)),
                c if c.is_ascii_alphabetic() || c == '_' => {
                    let ident = self.read_ident();
                    match ident.as_str() {
                        "true" => Ok(Token::Bool(true)),
                        "false" => Ok(Token::Bool(false)),
                        "null" => Ok(Token::Null),
                        "rec" => Ok(Token::Ident(ident)), // rec { } sets
                        _ => Ok(Token::Ident(ident)),
                    }
                }
                _ => {
                    let line = self.line;
                    self.advance();
                    Err(ExtosError::ConfigParse {
                        path: String::new(),
                        line,
                        message: format!("unexpected character: '{c}'"),
                    })
                }
            },
        }
    }

    fn read_number(&mut self) -> Result<i64, ExtosError> {
        let mut s = String::new();
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            s.push(self.advance().unwrap());
        }
        s.parse::<i64>().map_err(|e| ExtosError::ConfigParse {
            path: String::new(),
            line: self.line,
            message: format!("invalid integer: {e}"),
        })
    }

    fn read_ident(&mut self) -> String {
        let mut s = String::new();
        while self
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            s.push(self.advance().unwrap());
        }
        s
    }

    fn tokenize(&mut self) -> Result<Vec<Token>, ExtosError> {
        let mut tokens = Vec::new();
        loop {
            let tok = self.next_token()?;
            if tok == Token::Eof {
                tokens.push(Token::Eof);
                break;
            }
            tokens.push(tok);
        }
        Ok(tokens)
    }
}

// ─── Parser ─────────────────────────────────────────────────────

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    path: String,
}

impl Parser {
    fn new(tokens: Vec<Token>, path: String) -> Self {
        Self {
            tokens,
            pos: 0,
            path,
        }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> Token {
        let tok = self.tokens.get(self.pos).cloned().unwrap_or(Token::Eof);
        self.pos += 1;
        tok
    }

    fn expect(&mut self, expected: &Token) -> Result<(), ExtosError> {
        let got = self.advance();
        if &got != expected {
            Err(ExtosError::ConfigParse {
                path: self.path.clone(),
                line: 0,
                message: format!("expected {expected:?}, got {got:?}"),
            })
        } else {
            Ok(())
        }
    }

    /// Parse a top-level file. ExtOS configs are either:
    /// - A bare attribute set: `{ key = value; ... }`
    /// - Bare bindings without braces: `key = value; key2 = value2;`
    fn parse_file(&mut self) -> Result<NixValue, ExtosError> {
        match self.peek() {
            Token::LBrace => self.parse_value(),
            Token::Ident(s) if s == "rec" => {
                self.advance(); // consume 'rec'
                self.parse_attrset()
            }
            Token::Ident(_) => {
                // Bare bindings mode (e.g., `name = "foo"; version = "1.0";`)
                self.parse_bindings_to_eof()
            }
            Token::Eof => Ok(NixValue::AttrSet(BTreeMap::new())),
            _ => self.parse_value(),
        }
    }

    /// Parse bare `key = value;` bindings until EOF.
    ///
    /// As inside an attribute set, the last binding may omit its trailing
    /// `';'` when it is immediately followed by end of input.
    fn parse_bindings_to_eof(&mut self) -> Result<NixValue, ExtosError> {
        let mut map = BTreeMap::new();
        while *self.peek() != Token::Eof {
            self.parse_binding(&mut map)?;
            self.expect_binding_terminator(&Token::Eof, "end of input")?;
        }
        Ok(NixValue::AttrSet(map))
    }

    /// Consume the terminator that follows a binding's value.
    ///
    /// Nix-compatible: `';'` separates bindings, so the *last* binding of a
    /// collection may omit it when the closing token comes right next
    /// (`{ name = "glibc" }`). Between bindings the `';'` remains mandatory
    /// (`{ a = 1 b = 2 }` is still a parse error).
    fn expect_binding_terminator(
        &mut self,
        closer: &Token,
        closer_desc: &str,
    ) -> Result<(), ExtosError> {
        if *self.peek() == Token::Semi {
            self.advance();
            return Ok(());
        }
        if self.peek() == closer {
            return Ok(());
        }
        let got = self.peek().clone();
        Err(ExtosError::ConfigParse {
            path: self.path.clone(),
            line: 0,
            message: format!("expected ';' or {closer_desc} after binding value, got {got:?}"),
        })
    }

    /// Parse a single `key = value` or `key.sub.path = value` binding.
    ///
    /// The trailing `';'` is *not* consumed here; callers decide whether it
    /// may be omitted (see [`Parser::expect_binding_terminator`]).
    fn parse_binding(&mut self, map: &mut BTreeMap<String, NixValue>) -> Result<(), ExtosError> {
        // Read the key path: `key` or `key.sub.path`
        let mut path_parts = Vec::new();
        match self.advance() {
            Token::Ident(name) => path_parts.push(name),
            Token::String(name) => path_parts.push(name),
            other => {
                return Err(ExtosError::ConfigParse {
                    path: self.path.clone(),
                    line: 0,
                    message: format!("expected attribute name, got {other:?}"),
                });
            }
        }
        // Read dotted path
        while *self.peek() == Token::Dot {
            self.advance(); // consume dot
            match self.advance() {
                Token::Ident(name) => path_parts.push(name),
                Token::String(name) => path_parts.push(name),
                other => {
                    return Err(ExtosError::ConfigParse {
                        path: self.path.clone(),
                        line: 0,
                        message: format!("expected attribute name after '.', got {other:?}"),
                    });
                }
            }
        }

        self.expect(&Token::Equals)?;
        let value = self.parse_value()?;

        // Insert into nested map structure
        insert_dotted(map, &path_parts, value);
        Ok(())
    }

    /// Parse a single value expression.
    fn parse_value(&mut self) -> Result<NixValue, ExtosError> {
        match self.peek().clone() {
            Token::String(s) => {
                let s = s.clone();
                self.advance();
                Ok(NixValue::String(s))
            }
            Token::Int(n) => {
                let n = n;
                self.advance();
                Ok(NixValue::Int(n))
            }
            Token::Bool(b) => {
                let b = b;
                self.advance();
                Ok(NixValue::Bool(b))
            }
            Token::Null => {
                self.advance();
                Ok(NixValue::Null)
            }
            Token::LBracket => self.parse_list(),
            Token::LBrace => self.parse_attrset(),
            Token::Ident(ref s) if s == "rec" => {
                self.advance(); // consume 'rec'
                self.parse_attrset() // treat `rec { }` same as `{ }`
            }
            Token::Ident(s) => {
                // Bare identifier reference — store as string
                let s = s.clone();
                self.advance();
                // Check for dotted path: `extos.mkinitcpio`
                let mut path = s;
                while *self.peek() == Token::Dot {
                    self.advance();
                    if let Token::Ident(next) = self.advance() {
                        path.push('.');
                        path.push_str(&next);
                    }
                }
                Ok(NixValue::String(path))
            }
            other => Err(ExtosError::ConfigParse {
                path: self.path.clone(),
                line: 0,
                message: format!("unexpected token in value position: {other:?}"),
            }),
        }
    }

    /// Parse `[ value value ... ]`
    fn parse_list(&mut self) -> Result<NixValue, ExtosError> {
        self.expect(&Token::LBracket)?;
        let mut items = Vec::new();
        while *self.peek() != Token::RBracket {
            if *self.peek() == Token::Eof {
                return Err(ExtosError::ConfigParse {
                    path: self.path.clone(),
                    line: 0,
                    message: "unterminated list (missing ']')".into(),
                });
            }
            items.push(self.parse_value()?);
        }
        self.expect(&Token::RBracket)?;
        Ok(NixValue::List(items))
    }

    /// Parse `{ key = value; ... }`.
    ///
    /// The last binding may omit its trailing `';'` (Nix-compatible).
    fn parse_attrset(&mut self) -> Result<NixValue, ExtosError> {
        self.expect(&Token::LBrace)?;
        let mut map = BTreeMap::new();
        while *self.peek() != Token::RBrace {
            if *self.peek() == Token::Eof {
                return Err(ExtosError::ConfigParse {
                    path: self.path.clone(),
                    line: 0,
                    message: "unterminated attribute set (missing '}')".into(),
                });
            }
            self.parse_binding(&mut map)?;
            self.expect_binding_terminator(&Token::RBrace, "'}'")?;
        }
        self.expect(&Token::RBrace)?;
        Ok(NixValue::AttrSet(map))
    }
}

/// Insert a value at a dotted path (e.g., `["a", "b", "c"]` → `a.b.c = value`).
fn insert_dotted(map: &mut BTreeMap<String, NixValue>, parts: &[String], value: NixValue) {
    if parts.len() == 1 {
        map.insert(parts[0].clone(), value);
        return;
    }
    let entry = map
        .entry(parts[0].clone())
        .or_insert_with(|| NixValue::AttrSet(BTreeMap::new()));
    if let NixValue::AttrSet(inner) = entry {
        insert_dotted(inner, &parts[1..], value);
    }
}

// ─── Public API ─────────────────────────────────────────────────

/// Parse a `.nix` configuration string into a `NixValue`.
pub fn parse_nix(input: &str) -> Result<NixValue, ExtosError> {
    parse_nix_with_path(input, "<input>")
}

/// Parse a `.nix` configuration string with a file path for error reporting.
pub fn parse_nix_with_path(input: &str, path: &str) -> Result<NixValue, ExtosError> {
    let mut tokenizer = Tokenizer::new(input);
    let tokens = tokenizer.tokenize()?;
    let mut parser = Parser::new(tokens, path.to_string());
    parser.parse_file()
}

/// Parse a `.nix` file from disk.
pub fn parse_nix_file(path: &Path) -> Result<NixValue, ExtosError> {
    let content = std::fs::read_to_string(path)?;
    parse_nix_with_path(&content, &path.display().to_string())
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_attrset() {
        let input = r#"{
            name = "htop";
            version = "3.3.0-1";
            origin = "archlinux";
        }"#;
        let val = parse_nix(input).unwrap();
        assert_eq!(val.get_str("name"), Some("htop"));
        assert_eq!(val.get_str("version"), Some("3.3.0-1"));
        assert_eq!(val.get_str("origin"), Some("archlinux"));
    }

    #[test]
    fn test_nested_attrset() {
        let input = r#"{
            identity = {
                origin = "archlinux";
                name = "htop";
                version = "3.3.0-1";
                aliases = [ "htop-legacy" ];
            };
            format = "extracted-tree";
        }"#;
        let val = parse_nix(input).unwrap();
        assert_eq!(val.get_str("identity.origin"), Some("archlinux"));
        assert_eq!(val.get_str("identity.name"), Some("htop"));
        assert_eq!(
            val.get_str_list("identity.aliases"),
            Some(vec!["htop-legacy"])
        );
        assert_eq!(val.get_str("format"), Some("extracted-tree"));
    }

    #[test]
    fn test_dotted_paths() {
        let input = r#"{
            boot.loader = "systemd-boot";
            boot.timeout = 5;
            boot.kernel.origin = "extos";
        }"#;
        let val = parse_nix(input).unwrap();
        assert_eq!(val.get_str("boot.loader"), Some("systemd-boot"));
        assert_eq!(val.get_path("boot.timeout").and_then(|v| v.as_int()), Some(5));
        assert_eq!(val.get_str("boot.kernel.origin"), Some("extos"));
    }

    #[test]
    fn test_list_of_attrsets() {
        let input = r#"{
            requires = [
                { provides = "libncursesw.so.6"; }
                { provides = "libnl-3.so.20"; }
                { executable = "bash"; }
            ];
        }"#;
        let val = parse_nix(input).unwrap();
        let list = val.get_path("requires").unwrap().as_list().unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].get_str("provides"), Some("libncursesw.so.6"));
        assert_eq!(list[2].get_str("executable"), Some("bash"));
    }

    #[test]
    fn test_bare_bindings() {
        let input = r#"
            name = "hyprland";
            version = "0.39.1";
            origin = "archlinux";
            format = "extracted-tree";
        "#;
        let val = parse_nix(input).unwrap();
        assert_eq!(val.get_str("name"), Some("hyprland"));
        assert_eq!(val.get_str("format"), Some("extracted-tree"));
    }

    #[test]
    fn test_comments() {
        let input = r#"
            # This is a line comment
            name = "test"; /* inline block comment */
            /* multi-line
               block comment */
            version = "1.0";
        "#;
        let val = parse_nix(input).unwrap();
        assert_eq!(val.get_str("name"), Some("test"));
        assert_eq!(val.get_str("version"), Some("1.0"));
    }

    #[test]
    fn test_booleans_and_null() {
        let input = r#"{
            enabled = true;
            debug = false;
            extra = null;
        }"#;
        let val = parse_nix(input).unwrap();
        assert_eq!(val.get_path("enabled").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(val.get_path("debug").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(val.get_path("extra"), Some(&NixValue::Null));
    }

    #[test]
    fn test_negative_integer() {
        let input = r#"{ timeout = -1; count = 42; }"#;
        let val = parse_nix(input).unwrap();
        assert_eq!(val.get_path("timeout").and_then(|v| v.as_int()), Some(-1));
        assert_eq!(val.get_path("count").and_then(|v| v.as_int()), Some(42));
    }

    #[test]
    fn test_string_escapes() {
        let input = r#"{ msg = "hello\nworld\t\"quoted\""; }"#;
        let val = parse_nix(input).unwrap();
        assert_eq!(val.get_str("msg"), Some("hello\nworld\t\"quoted\""));
    }

    #[test]
    fn test_rec_attrset() {
        let input = r#"rec { name = "test"; value = 42; }"#;
        let val = parse_nix(input).unwrap();
        assert_eq!(val.get_str("name"), Some("test"));
        assert_eq!(val.get_path("value").and_then(|v| v.as_int()), Some(42));
    }

    #[test]
    fn test_identifier_reference() {
        // In ExtOS configs, bare identifiers like `extos.mkinitcpio`
        // are stored as string values.
        let input = r#"{
            provider = extos.mkinitcpio;
            compressor = "zstd";
        }"#;
        let val = parse_nix(input).unwrap();
        assert_eq!(val.get_str("provider"), Some("extos.mkinitcpio"));
    }

    #[test]
    fn test_manifest_nix_full() {
        let input = r#"
        {
            identity = {
                origin = "archlinux";
                name = "htop";
                version = "3.3.0-1";
                aliases = [ "htop-legacy" ];
            };

            format = "extracted-tree";

            capabilities = {
                binaries = [ "htop" ];
                resources = [ "/usr/share/applications/htop.desktop" ];
                virtual = [ "system-monitor" ];
            };

            requires = [
                { provides = "libncursesw.so.6"; }
                { provides = "libnl-3.so.20"; }
                { provides = "libnl-genl-3.so.20"; }
                { provides = "libc.so.6"; }
            ];

            suggests = {
                lsof-support = [
                    { executable = "lsof"; description = "show files opened by a process"; }
                ];
            };
        }
        "#;
        let val = parse_nix(input).unwrap();
        assert_eq!(val.get_str("identity.origin"), Some("archlinux"));
        assert_eq!(val.get_str("identity.name"), Some("htop"));
        assert_eq!(
            val.get_str_list("capabilities.binaries"),
            Some(vec!["htop"])
        );
        let requires = val.get_path("requires").unwrap().as_list().unwrap();
        assert_eq!(requires.len(), 4);
        assert_eq!(requires[0].get_str("provides"), Some("libncursesw.so.6"));
    }

    #[test]
    fn test_system_nix() {
        let input = r#"
        system = {
            name = "workstation-alpha";
            weaveMode = "reflink";
            init = { provider = extos.s6-linux-init; };
            packages = [
                { name = "base"; origin = "archlinux"; }
                { name = "hyprland"; origin = "archlinux"; }
                { name = "ffmpeg"; origin = "debian"; version = "6.0-1"; }
            ];
        };
        "#;
        let val = parse_nix(input).unwrap();
        assert_eq!(val.get_str("system.name"), Some("workstation-alpha"));
        assert_eq!(val.get_str("system.weaveMode"), Some("reflink"));
        let pkgs = val
            .get_path("system.packages")
            .unwrap()
            .as_list()
            .unwrap();
        assert_eq!(pkgs.len(), 3);
        assert_eq!(pkgs[2].get_str("origin"), Some("debian"));
    }

    #[test]
    fn test_empty_input() {
        let val = parse_nix("").unwrap();
        assert_eq!(val, NixValue::AttrSet(BTreeMap::new()));
    }

    #[test]
    fn test_empty_attrset() {
        let val = parse_nix("{}").unwrap();
        assert_eq!(val, NixValue::AttrSet(BTreeMap::new()));
    }

    #[test]
    fn test_empty_list() {
        let val = parse_nix("{ items = []; }").unwrap();
        assert_eq!(
            val.get_path("items"),
            Some(&NixValue::List(Vec::new()))
        );
    }

    // ── Nix-compatible optional trailing `;` on the last binding ──

    #[test]
    fn test_single_binding_without_trailing_semicolon() {
        let with_semi = parse_nix(r#"{ name = "glibc"; }"#).unwrap();
        let without_semi = parse_nix(r#"{ name = "glibc" }"#).unwrap();
        assert_eq!(without_semi, with_semi);
        assert_eq!(without_semi.get_str("name"), Some("glibc"));
    }

    #[test]
    fn test_last_binding_without_semicolon_after_other_bindings() {
        let val = parse_nix(r#"{ a = 1; b = 2 }"#).unwrap();
        assert_eq!(val.get_path("a").and_then(|v| v.as_int()), Some(1));
        assert_eq!(val.get_path("b").and_then(|v| v.as_int()), Some(2));
    }

    #[test]
    fn test_missing_semicolon_between_bindings_is_error() {
        // The invariant: `;` separates bindings and may only be omitted
        // before the closing `}` — never mid-listing.
        let err = parse_nix(r#"{ a = 1 b = 2 }"#).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("expected ';' or '}'"),
            "error message should be specific, got: {msg}"
        );
    }

    #[test]
    fn test_nested_manifest_without_any_trailing_semicolons() {
        // Only the *last* binding of each attrset omits its `;`; separators
        // between bindings are still present (Nix semantics).
        let input = r#"
        {
            system = {
                name = "workstation-alpha";
                weaveMode = "reflink";
                init = { provider = extos.s6-linux-init };
                packages = [
                    { name = "glibc" }
                    { name = "musl"; origin = "alpine"; version = "1.2.5-r0" }
                    { name = "busybox"; origin = "alpine" }
                ]
            }
        }
        "#;
        let val = parse_nix(input).unwrap();
        assert_eq!(val.get_str("system.name"), Some("workstation-alpha"));
        assert_eq!(val.get_str("system.weaveMode"), Some("reflink"));
        assert_eq!(
            val.get_str("system.init.provider"),
            Some("extos.s6-linux-init")
        );
        let pkgs = val.get_path("system.packages").unwrap().as_list().unwrap();
        assert_eq!(pkgs.len(), 3);
        assert_eq!(pkgs[0].get_str("name"), Some("glibc"));
        assert_eq!(pkgs[1].get_str("origin"), Some("alpine"));
        assert_eq!(pkgs[1].get_str("version"), Some("1.2.5-r0"));
        assert!(
            pkgs[0].get_path("origin").is_none(),
            "unexpected extra attribute in first package"
        );
    }

    #[test]
    fn test_package_list_without_trailing_semicolon() {
        // Exact shape of a commonly hand-written manifest snippet: the
        // one-binding attrsets carry no `;` and the list closes with `]`.
        let input = r#"{
            packages = [
                { name = "glibc" }
                { name = "musl"; origin = "alpine"; version = "1.2.5-r0" }
            ]
        }"#;
        let val = parse_nix(input).unwrap();
        let pkgs = val.get_path("packages").unwrap().as_list().unwrap();
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].get_str("name"), Some("glibc"));
        assert_eq!(pkgs[1].get_str("version"), Some("1.2.5-r0"));
    }

    #[test]
    fn test_bare_bindings_last_without_semicolon() {
        let val = parse_nix("name = \"hyprland\";\nversion = \"0.39.1\"").unwrap();
        assert_eq!(val.get_str("name"), Some("hyprland"));
        assert_eq!(val.get_str("version"), Some("0.39.1"));
    }

    #[test]
    fn test_bare_bindings_missing_semicolon_between_bindings_is_error() {
        let err = parse_nix("a = 1 b = 2").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("expected ';' or end of input"),
            "error message should be specific, got: {msg}"
        );
    }
}
