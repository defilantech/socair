package main

// asksForHelp reports whether a subcommand's arguments ask for help. The
// subcommands parse their own flags, and most take any flag they do not know
// as a bare one, so without this `socair serve --help` started the API,
// `socair airlock init --help` created a store at the default path, and
// `socair demo --help` wrote a report. A help flag anywhere after the
// subcommand prints the usage and does nothing else.
func asksForHelp(args []string) bool {
	for _, a := range args {
		if a == "--help" || a == "-h" {
			return true
		}
	}
	return false
}
