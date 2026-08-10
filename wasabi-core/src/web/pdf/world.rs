//! Custom `typst::World` implementation for server-side PDF rendering.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use chrono::{Datelike, Timelike};
use typst::diag::{FileError, FileResult};
use typst::foundations::{Bytes, Datetime, Duration};
use typst::syntax::{FileId, RootedPath, Source, VirtualPath, VirtualRoot};
use typst::text::{Font, FontBook};
use typst::utils::LazyHash;
use typst::{Library, World};
use typst_kit::fonts::FontStore;

use super::error::PdfError;
use super::schemes;

/// A minimal typst `World` for server-side PDF rendering.
///
/// Created fresh per `PdfRenderer::render()` call. Fonts and library are
/// shared across renders via `Arc`.
pub struct PdfWorld {
    main_source: Source,
    main_id: FileId,
    data: serde_json::Value,
    base_dir: Option<PathBuf>,
    fonts: Arc<FontStore>,
    library: Arc<LazyHash<Library>>,
    file_cache: Mutex<HashMap<FileId, Bytes>>,
}

impl PdfWorld {
    /// Create a new world for a single render pass.
    pub fn new(
        template: &str,
        data: serde_json::Value,
        base_dir: Option<PathBuf>,
        fonts: Arc<FontStore>,
        library: Arc<LazyHash<Library>>,
    ) -> Result<Self, PdfError> {
        let vpath = VirtualPath::new("/main.typ")
            .map_err(|e| PdfError::Template(format!("invalid main path: {e}")))?;
        let main_id = FileId::new(RootedPath::new(VirtualRoot::Project, vpath));
        let main_source = Source::new(main_id, template.to_string());

        Ok(Self {
            main_source,
            main_id,
            data,
            base_dir,
            fonts,
            library,
            file_cache: Mutex::new(HashMap::new()),
        })
    }

    /// Resolve a file based on its virtual path prefix.
    fn resolve_file(&self, id: FileId) -> FileResult<Bytes> {
        if let Ok(cache) = self.file_cache.lock()
            && let Some(bytes) = cache.get(&id)
        {
            return Ok(bytes.clone());
        }

        let vpath = id.vpath();
        let path_str = vpath.get_with_slash();

        let to_file_err = |e: super::error::PdfError| FileError::Other(Some(e.to_string().into()));

        let result = if path_str.starts_with("/data:") {
            Ok(schemes::resolve_data(&self.data))
        } else if let Some(data) = path_str.strip_prefix("/qr:/") {
            schemes::resolve_qr(data).map_err(to_file_err)
        } else if let Some(code) = path_str.strip_prefix("/ean:/") {
            schemes::resolve_ean(code).map_err(to_file_err)
        } else if let Some(rest) = path_str.strip_prefix("/https:") {
            let url = format!("https:{rest}");
            schemes::resolve_https(&url).map_err(to_file_err)
        } else if let Some(base) = &self.base_dir {
            let rootless = vpath.get_without_slash();
            schemes::resolve_local(base, rootless).map_err(to_file_err)
        } else {
            Err(FileError::Other(Some(
                format!("cannot resolve path: {path_str}").into(),
            )))
        };

        if let Ok(ref bytes) = result
            && let Ok(mut cache) = self.file_cache.lock()
        {
            let _ = cache.insert(id, bytes.clone());
        }

        result
    }
}

impl World for PdfWorld {
    fn library(&self) -> &LazyHash<Library> {
        &self.library
    }

    fn book(&self) -> &LazyHash<FontBook> {
        self.fonts.book()
    }

    fn main(&self) -> FileId {
        self.main_id
    }

    fn source(&self, id: FileId) -> FileResult<Source> {
        if id == self.main_id {
            Ok(self.main_source.clone())
        } else {
            Err(FileError::NotSource)
        }
    }

    fn file(&self, id: FileId) -> FileResult<Bytes> {
        self.resolve_file(id)
    }

    fn font(&self, index: usize) -> Option<Font> {
        self.fonts.font(index)
    }

    fn today(&self, offset: Option<Duration>) -> Option<Datetime> {
        let now = chrono::Local::now();
        let naive = match offset {
            Some(o) => {
                // typst hands us a `Duration`; recombine its components into a
                // total second offset (saturating, to stay panic-free) and add
                // it to UTC.
                let [weeks, days, hours, minutes, seconds] = o.decompose();
                let total_seconds = seconds
                    .saturating_add(minutes.saturating_mul(60))
                    .saturating_add(hours.saturating_mul(3600))
                    .saturating_add(days.saturating_mul(86_400))
                    .saturating_add(weeks.saturating_mul(604_800));
                let delta = chrono::Duration::try_seconds(total_seconds)?;
                now.naive_utc().checked_add_signed(delta)?
            }
            None => now.naive_local(),
        };

        Datetime::from_ymd_hms(
            naive.date().year(),
            naive.date().month() as u8,
            naive.date().day() as u8,
            naive.time().hour() as u8,
            naive.time().minute() as u8,
            naive.time().second() as u8,
        )
    }
}
