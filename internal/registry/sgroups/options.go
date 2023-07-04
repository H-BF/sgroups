package sgroups

// Option sync option
type Option interface {
	privateOption()
}

type (
	//SyncOmitInsert omit Insert op at sync
	SyncOmitInsert struct{ Option }

	//SyncOmitUpdate omit Update op at sync
	SyncOmitUpdate struct{ Option }

	//SyncOmitDelete omit Delete op at sync
	SyncOmitDelete struct{ Option }
)
