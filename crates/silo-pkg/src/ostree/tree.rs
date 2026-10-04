//! Completeness of a commit's tree.
//!
//! A commit names a root directory tree and metadata object; each tree
//! names its files and subdirectories by checksum. A repository that
//! serves a commit with any of those missing hands a client a half-app, so
//! a ref is only ever moved once everything under its commit is present.
//!
//! [`TreeWalk`] does the traversal without doing any I/O, so the same
//! logic checks a bundle's in-memory objects and objects an upload staged
//! in object storage. The caller asks what the walk wants next, fetches it
//! however it likes, and feeds it back:
//!
//! ```text
//! let mut walk = TreeWalk::new(&commit);
//! while let Some(want) = walk.next_wanted() {
//!     match want.ty {
//!         File => check it exists,
//!         _    => walk.provide(&want, &bytes_of(want))?,
//!     }
//! }
//! ```
//!
//! Traversal is iterative with an explicit queue and a visited set, so a
//! deep or heavily shared tree can neither overflow the stack nor be
//! walked twice.

use std::collections::{HashSet, VecDeque};

use super::gvariant::Error;
use super::object::{validate_dirmeta, Checksum, Commit, DirTree, ObjType};

type Result<T> = std::result::Result<T, Error>;

/// Deepest directory nesting a tree may have. Real application trees are
/// a few dozen levels deep; the bound exists so a crafted chain of
/// single-entry trees cannot make a checkout path arbitrarily long.
pub const MAX_DEPTH: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Want {
    pub ty: ObjType,
    pub checksum: Checksum,
    depth: usize,
}

pub struct TreeWalk {
    queue: VecDeque<Want>,
    seen: HashSet<(ObjType, Checksum)>,
}

impl TreeWalk {
    pub fn new(commit: &Commit) -> TreeWalk {
        let mut walk = TreeWalk {
            queue: VecDeque::new(),
            seen: HashSet::new(),
        };
        walk.enqueue(ObjType::DirMeta, commit.root_meta, 0);
        walk.enqueue(ObjType::DirTree, commit.root_tree, 0);
        walk
    }

    fn enqueue(&mut self, ty: ObjType, checksum: Checksum, depth: usize) {
        if self.seen.insert((ty, checksum)) {
            self.queue.push_back(Want {
                ty,
                checksum,
                depth,
            });
        }
    }

    /// The next object the walk needs to see, or `None` when every object
    /// under the commit has been accounted for.
    pub fn next_wanted(&mut self) -> Option<Want> {
        self.queue.pop_front()
    }

    /// Supplies a wanted metadata object's bytes. A directory tree's
    /// entries are queued in turn.
    ///
    /// The caller is responsible for the bytes having the checksum the
    /// walk asked for; this checks only that they are well-formed.
    pub fn provide(&mut self, want: &Want, bytes: &[u8]) -> Result<()> {
        match want.ty {
            ObjType::DirMeta => validate_dirmeta(bytes),
            ObjType::DirTree => {
                let tree = DirTree::parse(bytes)?;
                let child_depth = want.depth + 1;
                if !tree.dirs.is_empty() && child_depth > MAX_DEPTH {
                    return Err(Error(format!(
                        "the tree nests deeper than {MAX_DEPTH} directories"
                    )));
                }
                for (_, sum) in tree.files {
                    self.enqueue(ObjType::File, sum, child_depth);
                }
                for (_, tree_sum, meta_sum) in tree.dirs {
                    self.enqueue(ObjType::DirMeta, meta_sum, child_depth);
                    self.enqueue(ObjType::DirTree, tree_sum, child_depth);
                }
                Ok(())
            }
            other => Err(Error(format!("{other:?} objects are not walked"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ostree::delta::{read_bundle, Body};
    use crate::ostree::gvariant::Value;
    use crate::ostree::object::metadata_checksum;
    use std::collections::HashMap;

    fn walk_bundle(
        objects: &HashMap<(ObjType, Checksum), Vec<u8>>,
        commit: &Commit,
    ) -> Result<usize> {
        let mut walk = TreeWalk::new(commit);
        let mut visited = 0;
        while let Some(want) = walk.next_wanted() {
            visited += 1;
            let Some(bytes) = objects.get(&(want.ty, want.checksum)) else {
                return Err(Error(format!("missing {:?} {}", want.ty, want.checksum)));
            };
            if want.ty != ObjType::File {
                walk.provide(&want, bytes)?;
            }
        }
        Ok(visited)
    }

    fn objects_of(bundle: &crate::ostree::delta::Bundle) -> HashMap<(ObjType, Checksum), Vec<u8>> {
        bundle
            .objects
            .iter()
            .map(|o| {
                let bytes = match &o.body {
                    Body::Metadata(b) => b.clone(),
                    Body::File { content, .. } => content.clone(),
                };
                ((o.ty, o.checksum), bytes)
            })
            .collect()
    }

    #[test]
    fn a_complete_tree_is_walked_in_full() {
        let bundle = read_bundle(include_bytes!("../../tests/fixtures/hello.flatpak")).unwrap();
        let commit = Commit::parse(&bundle.commit).unwrap();
        // Everything but the commit: 2 files, 4 dirtrees, 1 dirmeta.
        assert_eq!(walk_bundle(&objects_of(&bundle), &commit).unwrap(), 7);
    }

    #[test]
    fn a_missing_object_is_reported() {
        let bundle = read_bundle(include_bytes!("../../tests/fixtures/hello.flatpak")).unwrap();
        let commit = Commit::parse(&bundle.commit).unwrap();
        let mut objects = objects_of(&bundle);
        let victim = *objects
            .keys()
            .find(|(ty, _)| *ty == ObjType::File)
            .expect("the bundle has files");
        objects.remove(&victim);
        let err = walk_bundle(&objects, &commit).unwrap_err();
        assert!(err.to_string().contains("missing"), "{err}");
    }

    /// A dirtree holding one directory entry.
    fn tree_with_dir(name: &str, tree: Checksum, meta: Checksum) -> Vec<u8> {
        use crate::ostree::gvariant::Ty;
        Value::Tuple(vec![
            Value::Array(Ty::parse("(say)").unwrap(), vec![]),
            Value::Array(
                Ty::parse("(sayay)").unwrap(),
                vec![Value::Tuple(vec![
                    Value::str(name),
                    Value::Bytes(tree.0.to_vec()),
                    Value::Bytes(meta.0.to_vec()),
                ])],
            ),
        ])
        .encode()
    }

    #[test]
    fn a_shared_subtree_is_visited_once() {
        let leaf = Value::Tuple(vec![
            Value::Array(crate::ostree::gvariant::Ty::parse("(say)").unwrap(), vec![]),
            Value::Array(
                crate::ostree::gvariant::Ty::parse("(sayay)").unwrap(),
                vec![],
            ),
        ])
        .encode();
        let leaf_sum = metadata_checksum(&leaf);
        let mut walk_target = TreeWalk {
            queue: VecDeque::new(),
            seen: HashSet::new(),
        };
        walk_target.enqueue(ObjType::DirTree, leaf_sum, 0);
        walk_target.enqueue(ObjType::DirTree, leaf_sum, 0);
        assert_eq!(walk_target.queue.len(), 1);
    }

    #[test]
    fn a_chain_deeper_than_the_limit_is_refused() {
        let mut walk = TreeWalk {
            queue: VecDeque::new(),
            seen: HashSet::new(),
        };
        let meta = Checksum([7; 32]);
        let mut depth = 0usize;
        let mut next = Checksum([1; 32]);
        walk.enqueue(ObjType::DirTree, next, 0);
        let result = loop {
            let want = walk.next_wanted().expect("the chain continues");
            if want.ty == ObjType::DirMeta {
                // Each level also names a directory metadata object; the
                // chain under test is the trees.
                continue;
            }
            let child = Checksum({
                let mut c = [0u8; 32];
                c[..8].copy_from_slice(&((depth + 2) as u64).to_le_bytes());
                c
            });
            let bytes = tree_with_dir("d", child, meta);
            match walk.provide(&want, &bytes) {
                Ok(()) => {
                    depth += 1;
                    next = child;
                    let _ = next;
                }
                Err(e) => break e,
            }
            assert!(depth <= MAX_DEPTH + 2, "the limit never tripped");
        };
        assert!(result.to_string().contains("deeper"), "{result}");
    }

    #[test]
    fn a_file_is_not_walked() {
        let mut walk = TreeWalk {
            queue: VecDeque::new(),
            seen: HashSet::new(),
        };
        let want = Want {
            ty: ObjType::File,
            checksum: Checksum([0; 32]),
            depth: 0,
        };
        assert!(walk.provide(&want, b"").is_err());
    }
}
