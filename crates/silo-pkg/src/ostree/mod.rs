//! OSTree and Flatpak wire formats.
//!
//! OSTree keeps everything — commits, directory trees, static deltas, the
//! repository `summary` — as GVariant; [`gvariant`] is the codec the rest
//! builds on, and [`object`] is the object model layered over it.
//!
//! [`delta`] opens a Flatpak bundle, [`archive`] encodes objects the way
//! an `archive` repository stores them, [`tree`] proves a commit's tree is
//! complete, and [`summary`] renders the files that make a set of objects
//! a remote.

pub mod archive;
pub mod delta;
pub mod gvariant;
pub mod object;
pub mod summary;
pub mod tree;
