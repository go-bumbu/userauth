package userdb

import (
	"sort"

	"gorm.io/gorm"
)

// GetGroups implements userauth.GroupsGetter. It returns the groups the user
// belongs to, sorted ascending. A user with no memberships (including an
// unknown user ID) yields an empty slice, not an error: absence of group data
// is a valid state, and callers have already resolved the user by the time
// they ask for groups.
func (s Store) GetGroups(userID string) ([]string, error) {
	var groups []string
	err := s.db.Model(&groupModel{}).Where("user_id = ?", userID).
		Order("group_name ASC").Pluck("group_name", &groups).Error
	return groups, err
}

// SetGroups implements userauth.GroupsSetter. It replaces all group
// memberships for the user in one transaction; an empty or nil slice removes
// the user from every group. Duplicates in the input are collapsed.
func (s Store) SetGroups(userID string, groups []string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		return s.setGroups(tx, userID, groups)
	})
}

// setGroups is the shared write path; tx may be the store handle or an
// enclosing transaction (e.g. createUser).
func (s Store) setGroups(tx *gorm.DB, userID string, groups []string) error {
	if err := tx.Where("user_id = ?", userID).Delete(&groupModel{}).Error; err != nil {
		return err
	}
	for _, g := range dedupeGroups(groups) {
		if err := tx.Create(&groupModel{UserID: userID, Group: g}).Error; err != nil {
			return err
		}
	}
	return nil
}

// dedupeGroups returns the unique non-empty group names, sorted, so writes are
// deterministic regardless of input order.
func dedupeGroups(groups []string) []string {
	seen := make(map[string]struct{}, len(groups))
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		if g == "" {
			continue
		}
		if _, ok := seen[g]; ok {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}
