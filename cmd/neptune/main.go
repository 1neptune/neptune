// Package main is the entry point of the Neptune encryption tool.
// It initializes and executes the root command from the cmd package.
package main

import "neptune/cmd/neptune/cmd"

// main is the program entry point.
// It delegates all command execution to the cmd package's Execute function,
// which handles command-line parsing, error handling, and program exit.
func main() {
	cmd.Execute()
}
