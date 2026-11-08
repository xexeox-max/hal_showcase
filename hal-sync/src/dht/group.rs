use std::collections::{HashMap, HashSet};

use crate::dht::NodeId;

pub type GroupId = u64;

/// Группа общения. Как закрытый чат в Telegram.
/// Членство = доступ к контенту группы, НЕ обход rate limit.
/// Trust — отдельная подсистема (TrustOracle).
#[derive(Debug, Clone)]
pub struct Group {
    pub id: GroupId,
    pub name: Option<String>,
    pub members: HashSet<NodeId>,
}

/// Абстракция групп. Модульность: замена реализации без
/// изменения TrustOracle.
pub trait GroupGraph: Send + Sync {
    /// В каких группах состоит узел.
    fn groups_of(&self, node_id: &NodeId) -> Vec<GroupId>;

    /// В любой ли группе узел.
    fn is_in_any_group(&self, node_id: &NodeId) -> bool;

    /// Есть ли пересечение групп между двумя узлами.
    fn share_group(&self, a: &NodeId, b: &NodeId) -> bool;
}

/// Реестр групп общения.
#[derive(Debug, Default)]
pub struct GroupRegistry {
    groups: HashMap<GroupId, Group>,
    next_id: GroupId,
}

impl GroupRegistry {
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
            next_id: 1,
        }
    }

    /// Создать группу. Возвращает id.
    pub fn create_group(&mut self, name: Option<String>) -> GroupId {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        self.groups.insert(
            id,
            Group {
                id,
                name,
                members: HashSet::new(),
            },
        );
        id
    }

    /// Удалить группу. Возвращает true, если была.
    pub fn remove_group(&mut self, id: GroupId) -> bool {
        self.groups.remove(&id).is_some()
    }

    /// Добавить участника. Возвращает true, если добавлен (false — уже был).
    pub fn add_member(&mut self, group_id: GroupId, node_id: NodeId) -> bool {
        match self.groups.get_mut(&group_id) {
            Some(group) => group.members.insert(node_id),
            None => false,
        }
    }

    /// Удалить участника. Возвращает true, если был.
    pub fn remove_member(&mut self, group_id: GroupId, node_id: &NodeId) -> bool {
        match self.groups.get_mut(&group_id) {
            Some(group) => group.members.remove(node_id),
            None => false,
        }
    }

    /// Получить группу.
    pub fn group_of(&self, id: GroupId) -> Option<&Group> {
        self.groups.get(&id)
    }

    /// Все группы.
    pub fn groups(&self) -> impl Iterator<Item = &Group> {
        self.groups.values()
    }

    /// Количество групп.
    pub fn len(&self) -> usize {
        self.groups.len()
    }

    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }
}

impl GroupGraph for GroupRegistry {
    fn groups_of(&self, node_id: &NodeId) -> Vec<GroupId> {
        self.groups
            .iter()
            .filter(|(_, group)| group.members.contains(node_id))
            .map(|(id, _)| *id)
            .collect()
    }

    fn is_in_any_group(&self, node_id: &NodeId) -> bool {
        self.groups
            .values()
            .any(|group| group.members.contains(node_id))
    }

    fn share_group(&self, a: &NodeId, b: &NodeId) -> bool {
        self.groups
            .values()
            .any(|group| group.members.contains(a) && group.members.contains(b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(seed: u8) -> NodeId {
        NodeId::from_bytes([seed; 32])
    }

    #[test]
    fn create_group_returns_unique_id() {
        let mut registry = GroupRegistry::new();
        let id1 = registry.create_group(Some("family".into()));
        let id2 = registry.create_group(Some("work".into()));
        assert_ne!(id1, id2);
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn add_member_and_check() {
        let mut registry = GroupRegistry::new();
        let id = registry.create_group(None);
        let n = node(1);

        assert!(registry.add_member(id, n));
        assert!(!registry.add_member(id, n));

        assert!(registry.is_in_any_group(&n));
        assert_eq!(registry.groups_of(&n), vec![id]);
    }

    #[test]
    fn remove_member() {
        let mut registry = GroupRegistry::new();
        let id = registry.create_group(None);
        let n = node(1);

        registry.add_member(id, n);
        assert!(registry.remove_member(id, &n));
        assert!(!registry.is_in_any_group(&n));
    }

    #[test]
    fn node_in_multiple_groups() {
        let mut registry = GroupRegistry::new();
        let family = registry.create_group(Some("family".into()));
        let bowling = registry.create_group(Some("bowling".into()));
        let n = node(2);

        registry.add_member(family, n);
        registry.add_member(bowling, n);

        let groups = registry.groups_of(&n);
        assert_eq!(groups.len(), 2);
        assert!(groups.contains(&family));
        assert!(groups.contains(&bowling));
    }

    #[test]
    fn share_group_between_nodes() {
        let mut registry = GroupRegistry::new();
        let id = registry.create_group(None);
        let a = node(1);
        let b = node(2);
        let c = node(3);

        registry.add_member(id, a);
        registry.add_member(id, b);

        assert!(registry.share_group(&a, &b));
        assert!(!registry.share_group(&a, &c));
    }

    #[test]
    fn remove_group_removes_membership() {
        let mut registry = GroupRegistry::new();
        let id = registry.create_group(None);
        let n = node(1);

        registry.add_member(id, n);
        assert!(registry.remove_group(id));
        assert!(!registry.is_in_any_group(&n));
    }

    #[test]
    fn add_member_to_nonexistent_group_returns_false() {
        let mut registry = GroupRegistry::new();
        assert!(!registry.add_member(999, node(1)));
    }
}
