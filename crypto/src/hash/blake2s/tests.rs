// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::Digest;

use super::{Blake2s_256, ElementHasher, Hasher};
use math::{fields::f62::BaseElement, fields::f64::BaseElement as Felt, FieldElement};
use rand_utils::rand_array;

#[test]
fn hash_padding() {
    let b1 = [1_u8, 2, 3];
    let b2 = [1_u8, 2, 3, 0];

    // adding a zero bytes at the end of a byte string should result in a different hash
    let r1 = Blake2s_256::<BaseElement>::hash(&b1);
    let r2 = Blake2s_256::<BaseElement>::hash(&b2);
    assert_ne!(r1, r2);
}

#[test]
fn hash_elements_padding() {
    let e1: [BaseElement; 2] = rand_array();
    let e2 = [e1[0], e1[1], BaseElement::ZERO];

    // adding a zero element at the end of a list of elements should result in a different hash
    let r1 = Blake2s_256::hash_elements(&e1);
    let r2 = Blake2s_256::hash_elements(&e2);
    assert_ne!(r1, r2);
}

#[test]
fn hash_elements_with_ser() {
    let b1 = [
        Felt::new(2541413064022245539),
        Felt::new(7129587402699328827),
        Felt::new(5589074863266416554),
        Felt::new(8033675306619022710),
    ];

    let r1 = Blake2s_256::hash_elements(&b1);
    println!("result:");
    for word in r1.0.chunks(4) {
        println!("{:x}", u32::from_le_bytes(word.try_into().unwrap()));
    }
}
