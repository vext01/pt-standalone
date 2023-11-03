# pt-standalone

A little Python script for making a stand-alone, redistributable, Intel PT
decoding environment.

Given a PT trace and a `/proc/<PID>/map` file, the script generates a directory
containing:
 - a copy of the trace
 - a copy of the map file (for reference only)
 - copies of all the required objects
 - a script containing a `ptxed` invocation for decoding the trace.
