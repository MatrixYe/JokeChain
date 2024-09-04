use sha2::{Digest, Sha256};
use std::collections::VecDeque;

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct MerkleNode {
    hash: Vec<u8>,
    left: Option<Box<MerkleNode>>,
    right: Option<Box<MerkleNode>>,
}

impl MerkleNode {
    fn new(hash: Vec<u8>) -> Self {
        MerkleNode {
            hash,
            left: None,
            right: None,
        }
    }

    fn new_parent(left: MerkleNode, right: MerkleNode) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&left.hash);
        hasher.update(&right.hash);
        let hash = hasher.finalize().to_vec();

        MerkleNode {
            hash,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
        }
    }
}

/// 默克尔树
#[derive(Debug)]
pub struct MerkleTree {
    root: Option<MerkleNode>,
}

impl MerkleTree {
    pub fn new(data: Vec<Vec<u8>>) -> Self {
        if data.is_empty() {
            return MerkleTree { root: None };
        }

        let mut nodes: VecDeque<MerkleNode> = data
            .into_iter()
            .map(|item| {
                let mut hasher = Sha256::new();
                hasher.update(&item);
                MerkleNode::new(hasher.finalize().to_vec())
            })
            .collect();

        while nodes.len() > 1 {
            let left = nodes.pop_front().unwrap();
            let right = nodes.pop_front().unwrap_or_else(|| left.clone());
            let parent = MerkleNode::new_parent(left, right);
            nodes.push_back(parent);
        }

        MerkleTree {
            root: nodes.pop_front(),
        }
    }

    pub fn root_hash(&self) -> Option<&[u8]> {
        self.root.as_ref().map(|node| node.hash.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree() {
        let data = vec![
            "交易1".as_bytes().to_vec(),
            "交易2".as_bytes().to_vec(),
            "交易3".as_bytes().to_vec(),
            "交易4".as_bytes().to_vec(),
        ];
        let tree = MerkleTree::new(data);
        assert!(tree.root_hash().is_some());
        println!("默克尔树根哈希: {:?}", tree.root_hash().unwrap());
    }
    #[test]
    fn test_empty_merkle_tree() {
        let data: Vec<Vec<u8>> = vec![];
        let tree = MerkleTree::new(data);
        assert!(tree.root_hash().is_none());
        println!("空默克尔树的根哈希应该为 None");
    }

    #[test]
    fn test_single_node_merkle_tree() {
        let data = vec!["单个交易".as_bytes().to_vec()];
        let tree = MerkleTree::new(data);
        assert!(tree.root_hash().is_some());
        println!("单节点默克尔树根哈希: {:?}", tree.root_hash().unwrap());
    }
}
