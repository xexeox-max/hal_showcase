use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PriorityLevel {
    Archived = 0,
    Normal = 1,
    High = 2,
    Manual = 3,
}

impl PriorityLevel {
    pub fn weight(self) -> f32 {
        match self {
            PriorityLevel::Archived => 0.1,
            PriorityLevel::Normal => 1.0,
            PriorityLevel::High => 5.0,
            PriorityLevel::Manual => 10.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityEntry {
    pub contact_id: String,
    pub level: PriorityLevel,
    pub manual_override: bool,
    pub last_activity_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PriorityRegistry {
    entries: HashMap<String, PriorityEntry>,
}

impl PriorityRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_manual(&mut self, contact_id: &str, level: PriorityLevel, now: u64) {
        let entry = self
            .entries
            .entry(contact_id.to_owned())
            .or_insert(PriorityEntry {
                contact_id: contact_id.to_owned(),
                level: PriorityLevel::Normal,
                manual_override: false,
                last_activity_at: now,
                updated_at: now,
            });
        entry.level = level;
        entry.manual_override = true;
        entry.updated_at = now;
    }

    pub fn clear_manual(&mut self, contact_id: &str, now: u64) {
        if let Some(entry) = self.entries.get_mut(contact_id) {
            entry.manual_override = false;
            entry.updated_at = now;
        }
    }

    pub fn record_activity(&mut self, contact_id: &str, now: u64) {
        let entry = self
            .entries
            .entry(contact_id.to_owned())
            .or_insert(PriorityEntry {
                contact_id: contact_id.to_owned(),
                level: PriorityLevel::Normal,
                manual_override: false,
                last_activity_at: now,
                updated_at: now,
            });
        entry.last_activity_at = now;
        entry.updated_at = now;
        if !entry.manual_override {
            entry.level = PriorityLevel::Normal;
        }
    }

    pub fn recompute_auto(&mut self, now: u64) {
        let active_cutoff = now.saturating_sub(AUTO_TOP_ACTIVE_DAYS * 24 * 60 * 60);
        let archive_cutoff = now.saturating_sub(AUTO_ARCHIVE_INACTIVE_DAYS * 24 * 60 * 60);

        for entry in self.entries.values_mut() {
            if entry.manual_override {
                continue;
            }
            entry.level = if entry.last_activity_at >= active_cutoff {
                PriorityLevel::High
            } else if entry.last_activity_at <= archive_cutoff {
                PriorityLevel::Archived
            } else {
                PriorityLevel::Normal
            };
            entry.updated_at = now;
        }
    }

    pub fn get(&self, contact_id: &str) -> Option<&PriorityEntry> {
        self.entries.get(contact_id)
    }

    pub fn level_of(&self, contact_id: &str) -> PriorityLevel {
        self.get(contact_id)
            .map(|entry| entry.level)
            .unwrap_or(PriorityLevel::Normal)
    }

    pub fn weight_of(&self, contact_id: &str) -> f32 {
        self.level_of(contact_id).weight()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

pub const AUTO_TOP_ACTIVE_DAYS: u64 = 7;
pub const AUTO_ARCHIVE_INACTIVE_DAYS: u64 = 30;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_empty_initially() {
        let registry = PriorityRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn set_manual_creates_entry() {
        let mut registry = PriorityRegistry::new();
        registry.set_manual("alice", PriorityLevel::Manual, 100);
        assert_eq!(registry.level_of("alice"), PriorityLevel::Manual);
        assert!(registry.get("alice").is_some());
    }

    #[test]
    fn clear_manual_keeps_auto() {
        let mut registry = PriorityRegistry::new();
        registry.set_manual("alice", PriorityLevel::Manual, 100);
        registry.clear_manual("alice", 200);
        assert!(!registry.get("alice").unwrap().manual_override);
        assert_eq!(registry.level_of("alice"), PriorityLevel::Manual);
    }

    #[test]
    fn record_activity_updates_timestamp() {
        let mut registry = PriorityRegistry::new();
        registry.record_activity("alice", 200);
        assert_eq!(registry.get("alice").unwrap().last_activity_at, 200);
    }

    #[test]
    fn recompute_auto_marks_active_as_high() {
        let mut registry = PriorityRegistry::new();
        registry.record_activity("alice", 1_000);
        registry.recompute_auto(1_000 + AUTO_TOP_ACTIVE_DAYS * 24 * 60 * 60 - 1);
        assert_eq!(registry.level_of("alice"), PriorityLevel::High);
    }

    #[test]
    fn recompute_auto_marks_inactive_as_archived() {
        let mut registry = PriorityRegistry::new();
        registry.record_activity("alice", 0);
        registry.recompute_auto(AUTO_ARCHIVE_INACTIVE_DAYS * 24 * 60 * 60 + 1);
        assert_eq!(registry.level_of("alice"), PriorityLevel::Archived);
    }

    #[test]
    fn recompute_auto_respects_manual_override() {
        let mut registry = PriorityRegistry::new();
        registry.set_manual("alice", PriorityLevel::Manual, 1_000);
        registry.record_activity("alice", 0);
        registry.recompute_auto(1_000_000);
        assert_eq!(registry.level_of("alice"), PriorityLevel::Manual);
    }

    #[test]
    fn weight_reflects_level() {
        assert_eq!(PriorityLevel::Archived.weight(), 0.1);
        assert_eq!(PriorityLevel::Normal.weight(), 1.0);
        assert_eq!(PriorityLevel::High.weight(), 5.0);
        assert_eq!(PriorityLevel::Manual.weight(), 10.0);
    }
}
