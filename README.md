# SMB3NTLMCrack
Automated script to construct and crack NTLMv2 hashes from encrypted SMB3 sessions.


Usage is simple, change final line of decrypt file to pcap location. If the user's password is too secure hashcat will stop after
2 hours. This can be edited manually and different hashcat commands may want to be used depending on the scenario.

Note: can currently only decrypt on session at a time, will be improved soon ™️
