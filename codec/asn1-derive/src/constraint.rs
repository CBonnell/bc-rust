//! The X.680 subtype constraint grammar, compiled to `const fn` interval-set expressions.

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{Error, LitStr, Result};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Value,
    Size,
    From,
}

pub struct Compiled {
    pub kind: Kind,
    pub set: TokenStream,
    /// An extension marker makes the constraint advisory.
    pub extensible: bool,
}

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Int(i128),
    Ident(String),
    Str(String),
    LParen,
    RParen,
    Pipe,
    Caret,
    DotDot,
    Ellipsis,
    Lt,
    Comma,
    Other(char),
}

fn lex(text: &str, span: Span) -> Result<Vec<Tok>> {
    let err = |m: &str| Error::new(span, format!("invalid constraint: {m}"));
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while let Some(&c) = chars.get(i) {
        match c {
            c if c.is_whitespace() => i += 1,
            '(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            '|' => {
                out.push(Tok::Pipe);
                i += 1;
            }
            '^' => {
                out.push(Tok::Caret);
                i += 1;
            }
            '<' => {
                out.push(Tok::Lt);
                i += 1;
            }
            ',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            '.' if chars.get(i + 1) == Some(&'.') && chars.get(i + 2) == Some(&'.') => {
                out.push(Tok::Ellipsis);
                i += 3;
            }
            '.' if chars.get(i + 1) == Some(&'.') => {
                out.push(Tok::DotDot);
                i += 2;
            }
            '"' => {
                let mut s = String::new();
                i += 1;
                loop {
                    match chars.get(i) {
                        Some('"') if chars.get(i + 1) == Some(&'"') => {
                            s.push('"');
                            i += 2;
                        }
                        Some('"') => {
                            i += 1;
                            break;
                        }
                        Some(&ch) => {
                            s.push(ch);
                            i += 1;
                        }
                        None => return Err(err("unterminated string")),
                    }
                }
                out.push(Tok::Str(s));
            }
            c if c.is_ascii_digit()
                || (c == '-' && chars.get(i + 1).is_some_and(char::is_ascii_digit)) =>
            {
                let start = i;
                i += 1;
                while chars.get(i).is_some_and(char::is_ascii_digit) {
                    i += 1;
                }
                let s: String = chars[start..i].iter().collect();
                out.push(Tok::Int(s.parse().map_err(|_| err("integer out of range"))?));
            }
            c if c.is_alphabetic() || c == '_' => {
                let start = i;
                while chars.get(i).is_some_and(|c| c.is_alphanumeric() || *c == '_' || *c == '-') {
                    i += 1;
                }
                // A trailing hyphen belongs to the next token (e.g. a range sign), not the name.
                while chars[start..i].last() == Some(&'-') {
                    i -= 1;
                }
                out.push(Tok::Ident(chars[start..i].iter().collect()));
            }
            other => {
                out.push(Tok::Other(other));
                i += 1;
            }
        }
    }
    Ok(out)
}

struct Parser {
    toks: Vec<Tok>,
    at: usize,
    span: Span,
    extensible: bool,
}

type Part = (Kind, TokenStream);

impl Parser {
    fn err<T>(&self, message: impl std::fmt::Display) -> Result<T> {
        Err(Error::new(self.span, format!("invalid constraint: {message}")))
    }

    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.at)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.at).cloned();
        self.at += 1;
        t
    }

    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek() == Some(t) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, t: &Tok) -> Result<()> {
        if self.eat(t) { Ok(()) } else { self.err(format!("expected {t:?}")) }
    }

    fn keyword(&self, word: &str) -> bool {
        matches!(self.peek(), Some(Tok::Ident(w)) if w == word)
    }

    fn combine(
        &self,
        a: Part,
        b: Part,
        op: fn(&TokenStream, &TokenStream) -> TokenStream,
    ) -> Result<Part> {
        if a.0 != b.0 {
            return self.err(
                "constraints of different kinds (value, SIZE, FROM) can't be combined in one \
                 expression; repeat the `constraint` attribute to intersect them",
            );
        }
        Ok((a.0, op(&a.1, &b.1)))
    }

    fn union(&mut self) -> Result<Part> {
        let mut left = self.intersection()?;
        while self.eat(&Tok::Pipe) || self.take_keyword("UNION") {
            let right = self.intersection()?;
            left = self.combine(left, right, |a, b| quote!(#a.union(&#b)))?;
        }
        Ok(left)
    }

    fn take_keyword(&mut self, word: &str) -> bool {
        if self.keyword(word) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn intersection(&mut self) -> Result<Part> {
        let mut left = self.except()?;
        while self.eat(&Tok::Caret) || self.take_keyword("INTERSECTION") {
            let right = self.except()?;
            left = self.combine(left, right, |a, b| quote!(#a.intersection(&#b)))?;
        }
        Ok(left)
    }

    fn except(&mut self) -> Result<Part> {
        let mut left = self.atom()?;
        while self.take_keyword("EXCEPT") {
            let right = self.atom()?;
            left = self.combine(left, right, |a, b| quote!(#a.except(&#b)))?;
        }
        Ok(left)
    }

    fn atom(&mut self) -> Result<Part> {
        if self.eat(&Tok::LParen) {
            let inner = self.set_with_extension()?;
            self.expect(&Tok::RParen)?;
            return Ok(inner);
        }
        if self.take_keyword("ALL") {
            if !self.take_keyword("EXCEPT") {
                return self.err("expected `EXCEPT` after `ALL`");
            }
            let excluded = self.atom()?;
            let all = quote!(::bouncycastle_asn1::IntervalSet::ALL);
            let set = &excluded.1;
            return Ok((excluded.0, quote!(#all.except(&#set))));
        }
        for (word, advice) in [
            ("CONTAINING", "use the `Containing<'a, T>` field type instead"),
            ("WITH", "use `validate = path` instead"),
            ("CONSTRAINED", "use `validate = path` instead"),
            ("PATTERN", "use `validate = path` instead"),
            ("INCLUDES", "use `validate = path` instead"),
        ] {
            if self.keyword(word) {
                return self.err(format!("`{word}` is not supported; {advice}"));
            }
        }
        if self.take_keyword("SIZE") {
            self.expect(&Tok::LParen)?;
            let inner = self.set_with_extension()?;
            self.expect(&Tok::RParen)?;
            if inner.0 != Kind::Value {
                return self.err("`SIZE` takes a set of integers");
            }
            return Ok((Kind::Size, inner.1));
        }
        if self.take_keyword("FROM") {
            self.expect(&Tok::LParen)?;
            let inner = self.set_with_extension()?;
            self.expect(&Tok::RParen)?;
            if inner.0 != Kind::From {
                return self.err("`FROM` takes quoted characters");
            }
            return Ok(inner);
        }
        self.element()
    }

    fn set_with_extension(&mut self) -> Result<Part> {
        let set = self.union()?;
        if self.eat(&Tok::Comma) {
            self.expect(&Tok::Ellipsis)?;
            self.extensible = true;
            if self.eat(&Tok::Comma) {
                // An additional element set after the marker is allowed and ignored.
                self.union()?;
            }
        }
        Ok(set)
    }

    fn bound(&mut self) -> Result<TokenStream> {
        match self.next() {
            Some(Tok::Int(v)) => Ok(quote!(#v)),
            Some(Tok::Ident(w)) if w == "MIN" => Ok(quote!(i128::MIN)),
            Some(Tok::Ident(w)) if w == "MAX" => Ok(quote!(i128::MAX)),
            Some(Tok::Ident(name)) => {
                let ident = syn::Ident::new(&name.replace('-', "_"), self.span);
                Ok(quote!((#ident as i128)))
            }
            other => self.err(format!("expected a value, found {other:?}")),
        }
    }

    fn element(&mut self) -> Result<Part> {
        if let Some(Tok::Str(s)) = self.peek().cloned() {
            self.at += 1;
            let mut chars = s.chars();
            let first = chars.next();
            if self.eat(&Tok::DotDot) {
                let Some(Tok::Str(hi)) = self.next() else {
                    return self.err("expected a quoted character after `..`");
                };
                let (Some(lo), Some(hi), 1, 1) =
                    (first, hi.chars().next(), s.chars().count(), hi.chars().count())
                else {
                    return self.err("character ranges take single characters");
                };
                let (lo, hi) = (lo as u32 as i128, hi as u32 as i128);
                return Ok((Kind::From, quote!(::bouncycastle_asn1::IntervalSet::range(#lo, #hi))));
            }
            let mut set = quote!(::bouncycastle_asn1::IntervalSet::EMPTY);
            for c in s.chars() {
                let v = c as u32 as i128;
                set = quote!(#set.union(&::bouncycastle_asn1::IntervalSet::single(#v)));
            }
            return Ok((Kind::From, set));
        }
        let lo = self.bound()?;
        let lt_after_lo = self.eat(&Tok::Lt);
        if self.eat(&Tok::DotDot) {
            let lt_before_hi = self.eat(&Tok::Lt);
            let hi = self.bound()?;
            let lo = if lt_after_lo { quote!(#lo + 1) } else { lo };
            let hi = if lt_before_hi { quote!(#hi - 1) } else { hi };
            return Ok((Kind::Value, quote!(::bouncycastle_asn1::IntervalSet::range(#lo, #hi))));
        }
        if lt_after_lo {
            return self.err("expected `..` after `<`");
        }
        Ok((Kind::Value, quote!(::bouncycastle_asn1::IntervalSet::single(#lo))))
    }
}

pub fn compile(text: &LitStr) -> Result<Compiled> {
    let span = text.span();
    let toks = lex(&text.value(), span)?;
    let mut p = Parser { toks, at: 0, span, extensible: false };
    let part = p.set_with_extension()?;
    // `(SIZE (1..4)) (FROM ("a".."z"))`-style serial constraints belong in repeated attributes.
    if p.at != p.toks.len() {
        return p.err(
            "unexpected trailing input; repeat the `constraint` attribute for serial constraints",
        );
    }
    Ok(Compiled { kind: part.0, set: part.1, extensible: p.extensible })
}

/// A boolean expression over the value `v` that is true when all `constraints` hold.
pub fn check_expr(constraints: &[LitStr], value: &TokenStream) -> Result<Vec<TokenStream>> {
    constraints
        .iter()
        .map(|text| {
            let c = compile(text)?;
            let set = &c.set;
            let call = match c.kind {
                Kind::Value => quote!(::bouncycastle_asn1::check_range),
                Kind::Size => quote!(::bouncycastle_asn1::check_size),
                Kind::From => quote!(::bouncycastle_asn1::check_alphabet),
            };
            let check = quote! {{
                const SET: ::bouncycastle_asn1::IntervalSet = #set;
                #call(&SET, #value)
            }};
            Ok(if c.extensible { quote!({ let _ = #check; true }) } else { check })
        })
        .collect()
}
