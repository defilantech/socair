package checks

// ArchiveRead is what one check read of an archive, entry by entry, handed
// to File inventory, which otherwise names every archive as unscanned. The
// pickle check reports one for a torch.save zip it PASSed. The engine passes
// it on only for the bytes that check read (a directory scan's snapshot), so
// the inventory never re-reads the archive or takes another check's word for
// a different file.
type ArchiveRead struct {
	// By names the check row that read the archive.
	By string
	// Read says what it read, for the inventory's notes.
	Read string
	// Unread names each entry, or comment, the check did not read, with the
	// reason. Any one keeps the archive unscanned.
	Unread []string
}
