package stakerdb

import "errors"

var (

	// For some reason, db on disk representation have changed
	ErrCorruptedTransactionsDb = errors.New("transactions db is corrupted")

	// The transaction we try update is not found in db
	ErrTransactionNotFound = errors.New("transaction not found")

	// The transaction we try to add already exists in db
	ErrDuplicateTransaction = errors.New("transaction already exists")
)
