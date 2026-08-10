//! PDF generation module powered by Typst.
//!
//! Provides a reusable `PdfRenderer` that compiles Typst templates with
//! injected JSON data into PDF documents. Supports custom URI schemes
//! for data injection, QR codes, EAN-13 barcodes, HTTPS resources,
//! and local files.

/// Error types for PDF generation.
pub mod error;
/// Resolver functions for custom URI schemes.
pub mod schemes;
/// Warp response helpers for PDF content.
pub mod warp;
mod world;

use std::path::PathBuf;
use std::sync::Arc;

use typst::utils::LazyHash;
use typst::{Library, LibraryExt as _};
use typst_kit::fonts::FontStore;
use typst_layout::PagedDocument;

use self::error::PdfError;
use self::world::PdfWorld;

/// Reusable PDF renderer powered by Typst.
///
/// Fonts and the standard library are initialized once and shared across
/// render calls. Each `render()` creates a fresh `PdfWorld`.
pub struct PdfRenderer {
    template: String,
    fonts: Arc<FontStore>,
    library: Arc<LazyHash<Library>>,
    base_dir: Option<PathBuf>,
}

impl PdfRenderer {
    /// Create a new renderer with the given Typst template source.
    pub fn new(template: &str) -> Self {
        // Only the embedded fonts are used; system fonts are intentionally
        // excluded so rendering is deterministic across deployments.
        let mut fonts = FontStore::new();
        fonts.extend(typst_kit::fonts::embedded());

        let library = Arc::new(LazyHash::new(Library::default()));

        Self {
            template: template.to_string(),
            fonts: Arc::new(fonts),
            library,
            base_dir: None,
        }
    }

    /// Set a base directory for resolving local file paths in templates.
    pub fn with_base_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.base_dir = Some(path.into());
        self
    }

    /// Render the template with the given JSON data, returning PDF bytes.
    pub fn render(&self, data: &serde_json::Value) -> Result<Vec<u8>, PdfError> {
        let world = PdfWorld::new(
            &self.template,
            data.clone(),
            self.base_dir.clone(),
            self.fonts.clone(),
            self.library.clone(),
        )?;

        let document: typst::diag::Warned<typst::diag::SourceResult<PagedDocument>> =
            typst::compile(&world);

        let document = document.output.map_err(|diagnostics| {
            let messages: Vec<String> = diagnostics.iter().map(|d| d.message.to_string()).collect();
            PdfError::Compile(messages.join("; "))
        })?;

        let options = typst_pdf::PdfOptions::default();
        typst_pdf::pdf(&document, &options).map_err(|diagnostics| {
            let messages: Vec<String> = diagnostics.iter().map(|d| d.message.to_string()).collect();
            PdfError::Compile(messages.join("; "))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_minimal_pdf() {
        let renderer = PdfRenderer::new("Hello, World!");
        let data = serde_json::json!({});
        let pdf = renderer.render(&data).unwrap();
        assert!(pdf.starts_with(b"%PDF"), "output should be a valid PDF");
    }

    #[test]
    fn test_render_with_data() {
        let template = r#"#let data = json("data://input")
Hello, #data.name!
"#;
        let renderer = PdfRenderer::new(template);
        let data = serde_json::json!({"name": "World"});
        let pdf = renderer.render(&data).unwrap();
        assert!(pdf.starts_with(b"%PDF"));
    }
}
