//! Deterministic splitter for the verification fixture corpus.
//!
//! The source library is retained only as generator input.  Test harnesses open
//! the per-case GDS files generated here; they never select cells from the
//! monolithic source.

use gdsverify::{read_gds_library, write_gds_library, GdsElement, GdsLibrary, GdsReadMode};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FixtureSpec {
    suite: String,
    id: String,
    cell: String,
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("engine crate must live at crates/engine")
        .to_path_buf()
}

fn fixture_root() -> PathBuf {
    repository_root().join("tests/fixtures")
}

fn read_manifest(root: &Path) -> Value {
    let bytes = std::fs::read(root.join("manifest.json")).expect("read fixture manifest");
    serde_json::from_slice(&bytes).expect("parse fixture manifest")
}

fn fixture_specs(manifest: &Value) -> Vec<FixtureSpec> {
    let mut specs = Vec::new();
    for suite in ["drc", "lvs", "erc", "pex"] {
        let cases = manifest
            .get(suite)
            .and_then(|section| section.get("cases"))
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("manifest section `{suite}.cases` must be an array"));
        for case in cases {
            specs.push(FixtureSpec {
                suite: suite.to_string(),
                id: case
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| panic!("{suite} case is missing a string ID"))
                    .to_string(),
                cell: case
                    .get("cell")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| panic!("{suite} case is missing a string cell"))
                    .to_string(),
            });
        }
    }
    specs.sort();
    specs
}

fn referenced_cells(library: &GdsLibrary, root: &str) -> BTreeSet<String> {
    let structures: BTreeMap<&str, _> = library
        .structures
        .iter()
        .map(|structure| (structure.name.as_str(), structure))
        .collect();
    let mut selected = BTreeSet::new();
    let mut pending = vec![root.to_string()];
    while let Some(name) = pending.pop() {
        if !selected.insert(name.clone()) {
            continue;
        }
        let structure = structures
            .get(name.as_str())
            .unwrap_or_else(|| panic!("source GDS has no structure `{name}`"));
        for element in &structure.elements {
            let child = match element {
                GdsElement::Sref(reference) => Some(&reference.structure),
                GdsElement::Aref(reference) => Some(&reference.structure),
                _ => None,
            };
            if let Some(child) = child {
                pending.push(child.clone());
            }
        }
    }
    selected
}

fn render_fixture(source: &GdsLibrary, spec: &FixtureSpec) -> Vec<u8> {
    let selected = referenced_cells(source, &spec.cell);
    let mut library = source.clone();
    library.name = format!("GPUVERIFY_{}", spec.id);
    library
        .structures
        .retain(|structure| selected.contains(&structure.name));
    assert!(
        library
            .structures
            .iter()
            .any(|structure| structure.name == spec.cell),
        "case {} lost top cell {}",
        spec.id,
        spec.cell
    );
    write_gds_library(&library).expect("serialize split fixture")
}

fn source_library(root: &Path) -> GdsLibrary {
    let bytes =
        std::fs::read(root.join("_source/conformance.gds")).expect("read source fixture library");
    // The source deliberately contains zero-area and self-intersecting DRC
    // cases. Compatibility mode preserves those boundaries so the always-on
    // polygon-validity check can diagnose them after splitting.
    read_gds_library(&bytes, GdsReadMode::Compatibility)
        .expect("parse source fixture library while preserving invalid cases")
}

fn fixture_path(root: &Path, spec: &FixtureSpec) -> PathBuf {
    root.join(&spec.suite).join(format!("{}.gds", spec.id))
}

fn top_cells(library: &GdsLibrary) -> Vec<String> {
    let referenced: BTreeSet<&str> = library
        .structures
        .iter()
        .flat_map(|structure| structure.elements.iter())
        .filter_map(|element| match element {
            GdsElement::Sref(reference) => Some(reference.structure.as_str()),
            GdsElement::Aref(reference) => Some(reference.structure.as_str()),
            _ => None,
        })
        .collect();
    library
        .structures
        .iter()
        .filter(|structure| !referenced.contains(structure.name.as_str()))
        .map(|structure| structure.name.clone())
        .collect()
}

#[test]
fn corpus_is_complete_strict_and_current() {
    let root = fixture_root();
    let manifest = read_manifest(&root);
    let specs = fixture_specs(&manifest);
    let source = source_library(&root);

    assert_eq!(specs.len(), 160, "fixture count changed; update PLAN.md");
    let mut identities = BTreeSet::new();
    let mut expected_paths = BTreeSet::new();

    for spec in &specs {
        assert!(
            identities.insert((spec.suite.clone(), spec.id.clone())),
            "duplicate fixture identity {}/{}",
            spec.suite,
            spec.id
        );
        let path = fixture_path(&root, spec);
        let relative = path
            .strip_prefix(&root)
            .expect("fixture below root")
            .to_path_buf();
        expected_paths.insert(relative);
        let actual = std::fs::read(&path)
            .unwrap_or_else(|error| panic!("read fixture {}: {error}", path.display()));
        let expected = render_fixture(&source, spec);
        assert_eq!(
            actual,
            expected,
            "fixture {} is stale; run the ignored regenerate_fixtures test",
            path.display()
        );

        let parsed = match read_gds_library(&actual, GdsReadMode::Strict) {
            Ok(parsed) => parsed,
            Err(strict_error) => read_gds_library(&actual, GdsReadMode::Compatibility)
                .unwrap_or_else(|compatibility_error| {
                    panic!(
                        "parse {}: strict={strict_error}; compatibility={compatibility_error}",
                        path.display()
                    )
                }),
        };
        assert_eq!(
            parsed.envelope,
            gdsverify::GdsEnvelope::complete(),
            "{} must retain a complete GDS record envelope",
            path.display()
        );
        assert_eq!(
            top_cells(&parsed),
            vec![spec.cell.clone()],
            "{} must expose only its case cell as top",
            path.display()
        );
        assert_eq!(parsed.units.database_unit_nm(), 1.0);
    }

    let mut actual_paths = BTreeSet::new();
    for suite in ["drc", "lvs", "erc", "pex"] {
        let directory = root.join(suite);
        for entry in std::fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
        {
            let path = entry.expect("read fixture directory entry").path();
            if path.extension().is_some_and(|extension| extension == "gds") {
                actual_paths.insert(
                    path.strip_prefix(&root)
                        .expect("fixture below root")
                        .to_path_buf(),
                );
            }
        }
    }
    assert_eq!(
        actual_paths, expected_paths,
        "orphaned or missing GDS fixtures"
    );
}

#[test]
#[ignore = "explicit fixture regeneration mutates checked-in binary artifacts"]
fn regenerate_fixtures() {
    let root = fixture_root();
    let manifest = read_manifest(&root);
    let source = source_library(&root);
    for spec in fixture_specs(&manifest) {
        let path = fixture_path(&root, &spec);
        std::fs::create_dir_all(path.parent().expect("fixture suite directory"))
            .expect("create fixture suite directory");
        std::fs::write(&path, render_fixture(&source, &spec))
            .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
    }
}
