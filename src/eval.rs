use crate::claim::AuthenticatedClaim;
use std::cmp::Ordering;

#[derive(Clone,PartialEq,PartialOrd)]
pub struct TrustLevel {
    pub level: f64
}

impl TrustLevel {
    pub fn new(level: f64) -> TrustLevel {
        assert!(level >= 0.0 && level <= 1.0);
        TrustLevel {level}
    }
}
impl Copy for TrustLevel {}

impl Ord for TrustLevel {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.level < other.level {
            return Ordering::Less;
        }
        if self.level > other.level {
            return Ordering::Greater;
        }
        return Ordering::Equal;
    }
}
impl Eq for TrustLevel {}


pub trait TrustPolicy {
    fn evaluate<I>(&self, claims: I) -> TrustLevel where I: Iterator<Item=AuthenticatedClaim>;
}
