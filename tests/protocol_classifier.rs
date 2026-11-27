//! Regression tests for frame classification (protocol layer, Phase 2 skeleton).
//!
//! Classifications depend only on link/frame headers; payload bytes are never
//! inspected.

use streamcrack::domain::{FrameClassification, classify_link_type, link_type_name};

#[test]
fn dot11_has_pending_decoder() {
    assert_eq!(
        classify_link_type(105),
        FrameClassification::DecoderPending { link_type: 105 }
    );
}

#[test]
fn other_link_types_are_unknown() {
    assert_eq!(
        classify_link_type(1),
        FrameClassification::UnknownLinkType { link_type: 1 }
    );
    assert_eq!(
        classify_link_type(999),
        FrameClassification::UnknownLinkType { link_type: 999 }
    );
}

#[test]
fn link_type_names_are_metadata_only() {
    assert_eq!(link_type_name(1), "Ethernet");
    assert_eq!(link_type_name(105), "IEEE 802.11");
    assert_eq!(link_type_name(127), "Radiotap");
    assert_eq!(link_type_name(42), "unknown");
}
