//! QR rendering.
//!
//! Done in Rust and returned as finished SVG markup so a secret never passes
//! through a JavaScript QR library, and so the page needs no external script.

use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};

/// Largest payload accepted. A QR code tops out around 2 953 bytes; refusing
/// early gives a clear message instead of an opaque encoder failure.
const MAX_LEN: usize = 2000;

pub fn svg(text: &str) -> Result<String, String> {
    if text.is_empty() {
        return Err("nothing to encode".into());
    }
    if text.len() > MAX_LEN {
        return Err(format!(
            "too long to encode as a QR code ({} bytes, maximum {MAX_LEN})",
            text.len()
        ));
    }

    // Quartile error correction: readable even when the screen is photographed
    // at an angle, without inflating the module count the way High would.
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::Q)
        .map_err(|e| format!("QR encoding failed: {e}"))?;

    let rendered = code
        .render::<svg::Color>()
        .min_dimensions(240, 240)
        .quiet_zone(true)
        .dark_color(svg::Color("#0b0d12"))
        .light_color(svg::Color("#ffffff"))
        .build();

    // The renderer emits an XML prolog. It is invalid inside an HTML document,
    // so strip everything before the root element.
    let start = rendered
        .find("<svg")
        .ok_or("the QR renderer produced no SVG element")?;
    Ok(rendered[start..].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_renders_svg_markup() {
        let out = svg("otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQ").unwrap();
        assert!(out.starts_with("<svg"));
        assert!(out.contains("</svg>"));
    }

    #[test]
    fn empty_and_oversized_payloads_are_refused() {
        assert!(svg("").is_err());
        assert!(svg(&"x".repeat(MAX_LEN + 1)).is_err());
    }

    #[test]
    fn unicode_payloads_encode() {
        assert!(svg("password: Ω≈ç√∫˜µ").is_ok());
    }
}
