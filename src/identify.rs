use pelite::PeView;

const MAX_NAME_LEN: usize = 80;

fn sanitise(name: &str) -> Option<String> {
    let base = name.rsplit(['\\', '/']).next().unwrap_or(name);

    let cleaned = base
        .chars()
        .take(MAX_NAME_LEN)
        .map(|c| match c {
            '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect::<String>();

    (!cleaned.is_empty()).then_some(cleaned)
}

fn dll_name_from_pdb_path(path: &str) -> Option<String> {
    let base = path.rsplit(['\\', '/']).next().unwrap_or(path);
    let stem = base.strip_suffix(".pdb").unwrap_or(base);
    if stem.is_empty() {
        return None;
    }

    sanitise(&format!("{stem}.dll"))
}

fn name_from_exports(view: PeView<'_>) -> Option<String> {
    let name = view.exports().ok()?.dll_name().ok()?.to_str().ok()?;

    name.to_ascii_lowercase()
        .ends_with(".dll")
        .then(|| sanitise(name))
        .flatten()
}

fn name_from_debug_directory(view: PeView<'_>) -> Option<String> {
    let path = view.debug().ok()?.pdb_file_name()?.to_str().ok()?;

    dll_name_from_pdb_path(path)
}

fn view(data: &[u8]) -> Option<PeView<'_>> {
    PeView::from_bytes(data).ok()
}

pub fn is_pe(data: &[u8]) -> bool {
    view(data).is_some()
}
pub fn identify_pe_name(data: &[u8]) -> Option<String> {
    let view = view(data)?;

    name_from_exports(view).or_else(|| name_from_debug_directory(view))
}
